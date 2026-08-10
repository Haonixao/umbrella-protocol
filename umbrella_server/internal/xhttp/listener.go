package xhttp

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

// udpSession хранит состояние UDP-relay для одного клиента (IP:port).
type udpSession struct {
	clientAddr *net.UDPAddr
	backend    *net.UDPConn
}

type quicFrontend struct {
	conn        *net.UDPConn
	filter      *allowedIPFilter
	dest        string
	authKey     []byte
	backend     string
	sessions    map[string]*udpSession
	sessionsMu  sync.RWMutex
	sessionWait map[string]chan struct{}
	waitMu      sync.Mutex
}

// bufferedConn позволяет "подсмотреть" данные и вернуть их обратно
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

type allowedIPFilter struct {
	mu      sync.RWMutex
	allowed map[string]bool
}

func (f *allowedIPFilter) normalizeIP(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ipStr
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.String()
	}
	return ip.String()
}

func (f *allowedIPFilter) isAllowed(ip string) bool {
	normalized := f.normalizeIP(ip)
	f.mu.RLock()
	defer f.mu.RUnlock()
	if len(f.allowed) == 0 {
		return false
	}
	return f.allowed[normalized]
}

func (f *allowedIPFilter) addAllowed(ip string) {
	normalized := f.normalizeIP(ip)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.allowed == nil {
		f.allowed = make(map[string]bool)
	}
	f.allowed[normalized] = true
	log.Printf("IP %s активирован", normalized)
}

type ipFilterListener struct {
	inner   net.Listener
	filter  *allowedIPFilter
	dest    string
	mode    string
	authKey []byte
}

func (l *ipFilterListener) Close() error {
	return l.inner.Close()
}

func (l *ipFilterListener) Addr() net.Addr {
	return l.inner.Addr()
}

func (l *ipFilterListener) isValidClient(br *bufio.Reader, host string) bool {
	header, err := br.Peek(5)
	if err != nil {
		log.Printf("[DEBUG] Peek(5) err: %v", err)
		return false
	}

	if header[0] != 0x16 {
		log.Printf("[DEBUG] Not TLS Handshake: %02x", header[0])
		return false
	}

	data, err := br.Peek(128)
	if err != nil {
		data, _ = br.Peek(br.Buffered())
	}

	if len(data) < 44 {
		log.Printf("[DEBUG] Packet too short: %d", len(data))
		return false
	}

	if data[5] != 0x01 {
		log.Printf("[DEBUG] Not ClientHello: %02x", data[5])
		return false
	}

	sessionIdLen := int(data[43])
	if sessionIdLen != 32 {
		log.Printf("[DEBUG] Invalid SessionID length: %d (expected 32)", sessionIdLen)
		return false
	}

	sessionId := data[44 : 44+32]

	// [0:5]  = random (5 байт)
	// [5:8]  = минуты с начала года (3 байта, big-endian)
	// [8:32] = HMAC (24 байта)

	randomBytes := sessionId[0:5]
	minutesBytes := sessionId[5:8]
	receivedMac := sessionId[8:32]

	actualMinBytes := make([]byte, 3)
	for i := 0; i < 3; i++ {
		actualMinBytes[i] = minutesBytes[i] ^ randomBytes[i]
	}

	// Преобразуем восстановленные байты в uint32
	minutesSinceYearStart := uint32(actualMinBytes[0])<<16 |
		uint32(actualMinBytes[1])<<8 |
		uint32(actualMinBytes[2])

	// Восстанавливаем примерное время
	yearStart := time.Date(time.Now().Year(), 1, 1, 0, 0, 0, 0, time.UTC)
	clientTime := yearStart.Add(time.Duration(minutesSinceYearStart) * time.Minute)

	// Проверяем временное окно (± 2.5 минуты)
	now := time.Now().UTC()
	if now.Sub(clientTime).Abs() > 2*time.Minute+30*time.Second {
		log.Printf("[DEBUG] Time drift: %v", now.Sub(clientTime).Abs())
		return false
	}

	sni, _, err := net.SplitHostPort(l.dest)
	if err != nil {
		log.Printf("[DEBUG] dest split: %v", err)
		return false
	}

	// Проверяем HMAC
	mac := hmac.New(sha256.New, l.authKey)
	mac.Write(randomBytes)
	mac.Write(actualMinBytes)
	mac.Write([]byte(sni))
	expectedMac := mac.Sum(nil)[:24]

	if !hmac.Equal(receivedMac, expectedMac) {
		return false
	}

	// Успешная проверка → добавляем IP в белый список
	l.filter.addAllowed(host)
	return true
}

func (l *ipFilterListener) Accept() (net.Conn, error) {
	for {
		c, err := l.inner.Accept()
		if err != nil {
			return nil, err
		}
		host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
		br := bufio.NewReader(c)

		if l.filter.isAllowed(host) {
			return &bufferedConn{Conn: c, r: br}, nil
		}

		if l.isValidClient(br, host) {
			log.Printf("[INFO] Valid client (Time+HMAC), forwarding → %s", host)
			return &bufferedConn{Conn: c, r: br}, nil
		}

		log.Printf("[INFO] Unknown client %s -> redirection to fallback", host)
		go l.transparentToSni(c, br)
	}
}

func (l *ipFilterListener) transparentToSni(client net.Conn, br *bufio.Reader) {
	defer client.Close()
	remote, err := net.Dial("tcp", l.dest)
	if err != nil {
		return
	}
	defer remote.Close()

	if br.Buffered() > 0 {
		peeked, _ := br.Peek(br.Buffered())
		remote.Write(peeked)
	}

	copyBufPtr := CopyBufPool.Get().(*[]byte)
	defer CopyBufPool.Put(copyBufPtr)
	copyBuf := *copyBufPtr

	done := make(chan struct{}, 2)
	go func() {
		io.CopyBuffer(remote, client, copyBuf)
		done <- struct{}{}
	}()
	go func() {
		buf2Ptr := CopyBufPool.Get().(*[]byte)
		defer CopyBufPool.Put(buf2Ptr)
		io.CopyBuffer(client, remote, *buf2Ptr)
		done <- struct{}{}
	}()
	<-done
}

func (q *quicFrontend) sessionKey(addr *net.UDPAddr) string {
	return addr.String()
}

func isQuicInitial(packet []byte) bool {
	if len(packet) < 6 {
		return false
	}
	return (packet[0]&0xC0 == 0xC0) && ((packet[0]>>4)&0x03 == 0x00)
}

func (q *quicFrontend) Start(addr string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}

	if err := conn.SetReadBuffer(8 * 1024 * 1024); err != nil {
		log.Printf("[ERR] QUIC Frontend: ReadBuffer: %v", err)
	}
	if err := conn.SetWriteBuffer(8 * 1024 * 1024); err != nil {
		log.Printf("[ERR] QUIC Frontend: WriteBuffer: %v", err)
	}

	q.conn = conn
	q.sessions = make(map[string]*udpSession)

	log.Printf("[INFO] QUIC Frontend %s (mask %s)", addr, q.dest)

	for {
		bufPtr := UDPBufPool.Get().(*[]byte)
		buf := *bufPtr

		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			UDPBufPool.Put(bufPtr)
			log.Printf("[ERR] QUIC Frontend read error: %v", err)
			continue
		}

		q.sessionsMu.RLock()
		sess := q.sessions[q.sessionKey(clientAddr)]
		q.sessionsMu.RUnlock()

		if sess != nil {
			sess.backend.SetReadDeadline(time.Now().Add(120 * time.Second))
			if _, err := sess.backend.Write(buf[:n]); err != nil {
				log.Printf("[ERR] write to backend: %v", err)
			}
			UDPBufPool.Put(bufPtr) // Сразу возвращаем
		} else {
			// Для нового пакета (Knock) копируем данные, так как handlePacket уйдет в горутину
			packet := make([]byte, n)
			copy(packet, buf[:n])
			UDPBufPool.Put(bufPtr)
			go q.handlePacket(packet, clientAddr)
		}
	}
}

func (q *quicFrontend) handlePacket(packet []byte, clientAddr *net.UDPAddr) {
	clientIP := clientAddr.IP.String()
	addrKey := q.sessionKey(clientAddr)

	if q.filter.isAllowed(clientIP) {
		// Защита от одновременного создания нескольких сессий для одного порта
		q.waitMu.Lock()
		waitCh, busy := q.sessionWait[addrKey]
		if busy {
			q.waitMu.Unlock()
			<-waitCh // Ждем, пока первая горутина создаст сессию
			q.sessionsMu.Lock()
			if sess, ok := q.sessions[addrKey]; ok {
				sess.backend.Write(packet)
			}
			q.sessionsMu.Unlock()
			return
		}
		waitCh = make(chan struct{})
		q.sessionWait[addrKey] = waitCh
		q.waitMu.Unlock()

		defer func() {
			q.waitMu.Lock()
			delete(q.sessionWait, addrKey)
			close(waitCh)
			q.waitMu.Unlock()
		}()

		q.forward(packet, clientAddr, q.backend, "quic-backend")
		return
	}

	if !isQuicInitial(packet) {
		log.Printf("[DEBUG] !isQuicInitial")
		return
	}

	dcidLen := int(packet[5])
	if len(packet) < 6+dcidLen {
		log.Printf("[DEBUG] len(packet) < 6+dcidLen")
		return
	}

	scidStart := 6 + dcidLen
	if len(packet) < scidStart+1 {
		log.Printf("[DEBUG] len(packet) < scidStart+1")
		return
	}
	scidLen := int(packet[scidStart])
	scidStart++

	if len(packet) < scidStart+scidLen {
		log.Printf("[DEBUG] len(packet) < scidStart+scidLen")
		return
	}

	scid := packet[scidStart : scidStart+scidLen]

	if len(scid) == 20 {
		rnd := scid[0:5]
		maskedTime := scid[5:8]
		receivedSig := scid[8:20]

		// 1. Восстанавливаем время через XOR
		minBytes := make([]byte, 3)
		for i := 0; i < 3; i++ {
			minBytes[i] = maskedTime[i] ^ rnd[i]
		}

		// 2. Проверяем временное окно (± 2.5 минуты)
		minutes := uint32(minBytes[0])<<16 | uint32(minBytes[1])<<8 | uint32(minBytes[2])
		now := time.Now().UTC()
		yearStart := time.Date(now.Year(), 1, 1, 0, 0, 0, 0, time.UTC)
		clientTime := yearStart.Add(time.Duration(minutes) * time.Minute)

		if now.Sub(clientTime).Abs() > 2*time.Minute+30*time.Second {
			log.Printf("[INFO] Decoy: CID time drift too high from %s", clientAddr.IP.String())
			q.forward(packet, clientAddr, q.dest, "fallback")
			return
		}

		sni, _, err := net.SplitHostPort(q.dest)
		if err != nil {
			log.Printf("[DEBUG] dest split: %v", err)
			return
		}

		// 3. Проверяем HMAC
		mac := hmac.New(sha256.New, q.authKey)
		mac.Write(rnd)
		mac.Write(minBytes)
		mac.Write([]byte(sni))
		expectedSig := mac.Sum(nil)[:12]

		if hmac.Equal(receivedSig, expectedSig) {
			log.Printf("[INFO] Valid client (Time+HMAC), forwarding → %s", clientAddr.IP.String())

			// АКТИВАЦИЯ: добавляем IP в общий белый список
			q.filter.addAllowed(clientAddr.IP.String())

			q.forward(packet, clientAddr, q.backend, "quic-backend")
			return
		} else {
			log.Printf("[DEBUG] !hmac.Equal(receivedSig, expectedSig)")
		}
	} else if len(scid) > 0 {
		log.Printf("[ERR] Unexpected SCID length: %d from %s", len(scid), clientAddr.IP.String())
	}

	log.Printf("[INFO] Unknown client, forwarding to dest → %s", clientAddr.IP.String())
	q.forward(packet, clientAddr, q.dest, "fallback")
}

func (q *quicFrontend) forward(packet []byte, clientAddr *net.UDPAddr, target string, label string) {
	targetAddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		log.Printf("[ERR] [quicFrontend] resolve %s: %v", target, err)
		return
	}

	backend, err := net.DialUDP("udp", nil, targetAddr)
	if err != nil {
		log.Printf("[ERR] [quicFrontend] dial %s: %v", target, err)
		return
	}

	backend.SetReadBuffer(8 * 1024 * 1024)
	backend.SetWriteBuffer(8 * 1024 * 1024)

	if _, err := backend.Write(packet); err != nil {
		log.Printf("[ERR] [quicFrontend] write to %s: %v", label, err)
		backend.Close()
		return
	}

	sess := &udpSession{
		clientAddr: clientAddr,
		backend:    backend,
	}
	q.sessionsMu.Lock()
	q.sessions[q.sessionKey(clientAddr)] = sess
	q.sessionsMu.Unlock()

	go q.proxyUDP(sess, label)
}

func (q *quicFrontend) proxyUDP(sess *udpSession, label string) {
	defer func() {
		q.sessionsMu.Lock()
		delete(q.sessions, q.sessionKey(sess.clientAddr))
		q.sessionsMu.Unlock()
		sess.backend.Close()
	}()

	for {
		bufPtr := UDPBufPool.Get().(*[]byte)
		buf := *bufPtr

		sess.backend.SetReadDeadline(time.Now().Add(120 * time.Second))
		n, err := sess.backend.Read(buf)
		if err != nil {
			UDPBufPool.Put(bufPtr)
			return
		}

		if _, err := q.conn.WriteToUDP(buf[:n], sess.clientAddr); err != nil {
			UDPBufPool.Put(bufPtr)
			return
		}
		UDPBufPool.Put(bufPtr)
	}
}
