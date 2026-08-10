package torrent

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	mrand "math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
	"umbrella_server/internal/config"

	"github.com/anacrolix/utp"
	"github.com/hashicorp/yamux"
)

const (
	pstr         = "BitTorrent protocol"
	pstrlen      = 19
	handshakeLen = 68
	pieceMsgID   = 7
	unchokeMsgID = 1
	bitfieldID   = 5
	requestID    = 6
)

var (
	gAuthKey    []byte
	gInfoHash   [20]byte
	copyBufPool = sync.Pool{New: func() any { b := make([]byte, 32*1024); return &b }}
	udpBufPool  = sync.Pool{New: func() any { b := make([]byte, 66*1024); return &b }}
)

func TorrentStarter(cfg *config.Config) {
	if cfg.Torrent.AuthKey == "" {
		log.Fatalf("[ERR] torrent auth-key is required")
	}
	authKey, err := hex.DecodeString(cfg.Torrent.AuthKey)
	if err != nil || len(authKey) != 32 {
		log.Fatalf("[ERR] invalid torrent auth-key: must be 64 hex chars (32 bytes)")
	}
	gAuthKey = authKey

	if cfg.Torrent.InfoHash != "" {
		ih, err := hex.DecodeString(cfg.Torrent.InfoHash)
		if err != nil || len(ih) != 20 {
			log.Fatalf("[ERR] invalid torrent info-hash: must be 40 hex chars (20 bytes)")
		}
		copy(gInfoHash[:], ih)
	}

	host, portStr, err := net.SplitHostPort(cfg.Port)
	if err != nil {
		host = "0.0.0.0"
		portStr = cfg.Port
	}

	var ports []int
	if strings.Contains(portStr, "-") {
		parts := strings.Split(portStr, "-")
		start, _ := strconv.Atoi(parts[0])
		end, _ := strconv.Atoi(parts[1])
		for i := start; i <= end; i++ {
			ports = append(ports, i)
		}
	} else {
		p, _ := strconv.Atoi(portStr)
		ports = append(ports, p)
	}

	log.Printf("[INFO] Umbrella/Torrent server listening on ports %s", portStr)
	for _, p := range ports {
		go func(port int) {
			s, err := utp.NewSocket("udp", net.JoinHostPort(host, strconv.Itoa(port)))
			if err != nil {
				log.Printf("[ERR] failed to listen on port %d: %v", port, err)
				return
			}
			for {
				conn, err := s.Accept()
				if err != nil {
					continue
				}
				go handleTorrentConn(conn)
			}
		}(p)
	}

	select {}
}

func handleTorrentConn(conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[Panic] handleTorrentConn from %s: %v", conn.RemoteAddr(), r)
		}
		conn.Close()
	}()
	log.Printf("[INFO] Incoming connection from %s", conn.RemoteAddr())
	// 1. Read BitTorrent Handshake
	handshake := make([]byte, handshakeLen)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(conn, handshake); err != nil {
		return
	}
	conn.SetReadDeadline(time.Time{})

	if handshake[0] != pstrlen || string(handshake[1:20]) != pstr {
		return
	}

	clientInfoHash := handshake[28:48]
	peerID := handshake[48:68] // Последние 20 байт

	// --- НОВАЯ ЛОГИКА АВТОРИЗАЦИИ ---

	// 1. Извлекаем компоненты из PeerID
	// [0:8]   = "-TR4000-" (статический префикс)
	// [8:12]  = Rnd (4 байта)
	// [12:15] = MaskedTime (3 байта)
	// [15:20] = Signature (5 байт)

	rnd := peerID[8:12]
	maskedTime := peerID[12:15]
	signature := peerID[15:20]

	// 2. Снимаем маску XOR с времени, используя rnd
	minBytes := make([]byte, 3)
	for i := 0; i < 3; i++ {
		minBytes[i] = maskedTime[i] ^ rnd[i]
	}

	// 3. Проверяем временное окно (UTC)
	minutesSinceYearStart := uint32(minBytes[0])<<16 | uint32(minBytes[1])<<8 | uint32(minBytes[2])
	now := time.Now().UTC()
	yearStart := time.Date(now.Year(), 1, 1, 0, 0, 0, 0, time.UTC)
	clientTime := yearStart.Add(time.Duration(minutesSinceYearStart) * time.Minute)

	// Окно ± 2.5 минуты
	if now.Sub(clientTime).Abs() > 2*time.Minute+30*time.Second {
		log.Printf("[INFO] Decoy: time drift too high from %s", conn.RemoteAddr())
		beRealTorrentPeer(conn, clientInfoHash)
		return
	}

	// 4. Проверяем подпись HMAC (rnd + real_minutes + infohash)
	mac := hmac.New(sha1.New, gAuthKey)
	mac.Write(rnd)
	mac.Write(minBytes)
	mac.Write(clientInfoHash)
	expectedSig := mac.Sum(nil)[:5]

	if hmac.Equal(signature, expectedSig) {
		// Успешная авторизация
		respHandshake := make([]byte, handshakeLen)
		respHandshake[0] = pstrlen
		copy(respHandshake[1:20], pstr)
		copy(respHandshake[28:48], clientInfoHash)
		copy(respHandshake[48:56], []byte("-UM1000-"))
		rand.Read(respHandshake[56:68])
		conn.Write(respHandshake)

		// Передаем rnd в качестве nonce для инициализации AES-CTR
		handleUmbrellaSess(conn, rnd)
	} else {
		// Неверная подпись — уходим в режим приманки
		beRealTorrentPeer(conn, clientInfoHash)
	}
}

func handleUmbrellaSess(conn net.Conn, nonce []byte) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[Panic] handleUmbrellaSess from %s: %v", conn.RemoteAddr(), r)
		}
	}()

	bitfieldSize := 100 + mrand.Intn(400)
	bf := make([]byte, 4+1+bitfieldSize)
	binary.BigEndian.PutUint32(bf[0:4], uint32(1+bitfieldSize))
	bf[4] = bitfieldID
	for i := 0; i < bitfieldSize; i++ {
		bf[5+i] = 0xFF
	}
	for i := 0; i < 3; i++ {
		bf[5+mrand.Intn(bitfieldSize)] &= ^(1 << uint(mrand.Intn(8)))
	}
	conn.Write(bf)
	conn.Write([]byte{0, 0, 0, 1, unchokeMsgID})

	tConn := NewTorrentConn(conn, gAuthKey, gInfoHash, nonce)
	muxCfg := yamux.DefaultConfig()
	muxCfg.MaxStreamWindowSize = 8 * 1024 * 1024
	muxCfg.EnableKeepAlive = true
	muxCfg.StreamCloseTimeout = 10 * time.Second
	muxCfg.LogOutput = io.Discard

	muxSess, err := yamux.Server(tConn, muxCfg)
	if err != nil {
		log.Printf("[ERR] yamux server %s: %v", conn.RemoteAddr(), err)
		return
	}
	defer muxSess.Close()

	log.Printf("[INFO] Torrent Umbrella session from %s", conn.RemoteAddr())
	for {
		stream, err := muxSess.Accept()
		if err != nil {
			log.Printf("[INFO] Torrent session %s closed: %v", conn.RemoteAddr(), err)
			break
		}
		go handleStream(stream, conn.RemoteAddr())
	}
}

func handleStream(stream net.Conn, clientAddr net.Addr) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[Panic] torrent handleStream from %s: %v", clientAddr, r)
		}
		stream.Close()
	}()

	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(stream, lenBuf); err != nil {
		return
	}
	targetLen := binary.BigEndian.Uint32(lenBuf)
	if targetLen > 1024 {
		return
	}
	targetBytes := make([]byte, targetLen)
	if _, err := io.ReadFull(stream, targetBytes); err != nil {
		return
	}
	target := string(targetBytes)

	if target == "UDP_RELAY" {
		handleUDPRelay(stream)
	} else if target == "DNS_QUERY" {
		handleDNSQuery(stream, clientAddr)
	} else {
		handleTunnel(stream, target)
	}
}

func handleTunnel(conn net.Conn, target string) {
	remote, err := net.DialTimeout("tcp", target, 30*time.Second)
	if err != nil {
		return
	}
	defer remote.Close()

	log.Printf("[INFO] Torrent Proxying %s → %s", conn.RemoteAddr(), target)

	done := make(chan struct{}, 2)
	go func() {
		b := copyBufPool.Get().(*[]byte)
		defer copyBufPool.Put(b)
		io.CopyBuffer(remote, conn, *b)
		if cw, ok := remote.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		b := copyBufPool.Get().(*[]byte)
		defer copyBufPool.Put(b)
		io.CopyBuffer(conn, remote, *b)
		if cw, ok := conn.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}

func handleUDPRelay(stream net.Conn) {
	pc, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		return
	}
	defer pc.Close()

	const idleTimeout = 30 * time.Second
	done := make(chan struct{})

	go func() {
		defer close(done)
		lenBuf := make([]byte, 4)
		addrCache := make(map[string]*net.UDPAddr)

		bufPtr := udpBufPool.Get().(*[]byte)
		defer udpBufPool.Put(bufPtr)
		payloadBuf := *bufPtr

		for {
			stream.SetReadDeadline(time.Now().Add(idleTimeout))
			if _, err := io.ReadFull(stream, lenBuf); err != nil {
				return
			}
			payloadLen := binary.BigEndian.Uint32(lenBuf)
			if payloadLen > 65535 {
				return
			}
			payload := payloadBuf[:payloadLen]
			if _, err := io.ReadFull(stream, payload); err != nil {
				return
			}

			if len(payload) < 4 {
				continue
			}
			off := 0
			var host string
			switch payload[off] {
			case 0x01:
				if len(payload) < 7 {
					continue
				}
				host = net.IP(payload[1:5]).String()
				off = 5
			case 0x03:
				nameLen := int(payload[1])
				if len(payload) < 2+nameLen+2 {
					continue
				}
				host = string(payload[2 : 2+nameLen])
				off = 2 + nameLen
			case 0x04:
				if len(payload) < 19 {
					continue
				}
				host = net.IP(payload[1:17]).String()
				off = 17
			default:
				continue
			}
			port := binary.BigEndian.Uint16(payload[off : off+2])
			data := payload[off+2:]
			target := net.JoinHostPort(host, fmt.Sprintf("%d", port))

			addr, ok := addrCache[target]
			if !ok {
				addr, _ = net.ResolveUDPAddr("udp", target)
				if len(addrCache) > 1000 {
					for k := range addrCache {
						delete(addrCache, k)
						break
					}
				}
				addrCache[target] = addr
			}
			if addr != nil {
				pc.SetWriteDeadline(time.Now().Add(5 * time.Second))
				pc.WriteTo(data, addr)
			}
		}
	}()

	bufPtr := udpBufPool.Get().(*[]byte)
	defer udpBufPool.Put(bufPtr)
	buf := *bufPtr

	frameBufPtr := udpBufPool.Get().(*[]byte)
	defer udpBufPool.Put(frameBufPtr)
	frameBuf := *frameBufPtr

	for {
		select {
		case <-done:
			return
		default:
		}
		pc.SetReadDeadline(time.Now().Add(idleTimeout))
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		udpAddr := addr.(*net.UDPAddr)
		off := 4
		if ip4 := udpAddr.IP.To4(); ip4 != nil {
			frameBuf[off] = 0x01
			copy(frameBuf[off+1:], ip4)
			off += 5
		} else {
			frameBuf[off] = 0x04
			copy(frameBuf[off+1:], udpAddr.IP.To16())
			off += 17
		}
		binary.BigEndian.PutUint16(frameBuf[off:off+2], uint16(udpAddr.Port))
		off += 2
		copy(frameBuf[off:], buf[:n])
		off += n
		binary.BigEndian.PutUint32(frameBuf[0:4], uint32(off-4))

		stream.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := stream.Write(frameBuf[:off]); err != nil {
			return
		}
	}
}

func handleDNSQuery(stream net.Conn, clientAddr net.Addr) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(stream, lenBuf); err != nil {
		return
	}
	payloadLen := binary.BigEndian.Uint32(lenBuf)
	if payloadLen > 65535 {
		return
	}
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(stream, payload); err != nil {
		return
	}

	off := 0
	var host string
	switch payload[off] {
	case 0x01:
		host = net.IP(payload[1:5]).String()
		off = 5
	case 0x03:
		nameLen := int(payload[1])
		host = string(payload[2 : 2+nameLen])
		off = 2 + nameLen
	case 0x04:
		host = net.IP(payload[1:17]).String()
		off = 17
	default:
		return
	}
	port := binary.BigEndian.Uint16(payload[off : off+2])
	dnsData := payload[off+2:]

	target := net.JoinHostPort(host, strconv.Itoa(int(port)))

	conn, err := net.DialTimeout("udp", target, 5*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()

	if _, err := conn.Write(dnsData); err != nil {
		return
	}

	resp := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(resp)
	if err != nil {
		return
	}

	headerBuf := make([]byte, 4+1+16+2+len(resp))
	off = 4

	var udpSrcIP net.IP
	var udpSrcPort int
	if ua, ok := clientAddr.(*net.UDPAddr); ok {
		udpSrcIP = ua.IP
		udpSrcPort = ua.Port
	} else {
		h, pStr, _ := net.SplitHostPort(clientAddr.String())
		udpSrcIP = net.ParseIP(h)
		udpSrcPort, _ = strconv.Atoi(pStr)
	}

	if ip4 := udpSrcIP.To4(); ip4 != nil {
		headerBuf[off] = 0x01
		copy(headerBuf[off+1:], ip4)
		off += 5
	} else {
		headerBuf[off] = 0x04
		copy(headerBuf[off+1:], udpSrcIP.To16())
		off += 17
	}
	binary.BigEndian.PutUint16(headerBuf[off:off+2], uint16(udpSrcPort))
	off += 2
	copy(headerBuf[off:], resp[:n])
	off += n
	binary.BigEndian.PutUint32(headerBuf[0:4], uint32(off-4))

	stream.Write(headerBuf[:off])
}

func beRealTorrentPeer(conn net.Conn, infoHash []byte) {
	defer conn.Close()
	log.Printf("[INFO] Decoy: unknown client from %s with infohash %s", conn.RemoteAddr(), hex.EncodeToString(infoHash))

	respHandshake := make([]byte, handshakeLen)
	respHandshake[0] = pstrlen
	copy(respHandshake[1:20], pstr)
	copy(respHandshake[28:48], infoHash)
	copy(respHandshake[48:56], []byte("-TR3000-"))
	rand.Read(respHandshake[56:68])
	if _, err := conn.Write(respHandshake); err != nil {
		return
	}

	bitfieldSize := 100 + mrand.Intn(400)
	bf := make([]byte, 4+1+bitfieldSize)
	binary.BigEndian.PutUint32(bf[0:4], uint32(1+bitfieldSize))
	bf[4] = bitfieldID
	for i := 0; i < bitfieldSize; i++ {
		bf[5+i] = 0xFF
	}
	for i := 0; i < 3; i++ {
		bf[5+mrand.Intn(bitfieldSize)] &= ^(1 << uint(mrand.Intn(8)))
	}
	conn.Write(bf)
	conn.Write([]byte{0, 0, 0, 1, unchokeMsgID})

	buf := make([]byte, 4096)
	for {
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		if n >= 4 {
			msgLen := binary.BigEndian.Uint32(buf[:4])
			if msgLen == 0 {
				conn.Write([]byte{0, 0, 0, 0})
				continue
			}
			if n >= 5 && buf[4] == requestID && n >= 17 {
				index := binary.BigEndian.Uint32(buf[5:9])
				begin := binary.BigEndian.Uint32(buf[9:13])
				length := binary.BigEndian.Uint32(buf[13:17])
				if length <= 32768 {
					pieceBuf := make([]byte, 4+1+4+4+int(length))
					binary.BigEndian.PutUint32(pieceBuf[0:4], uint32(9+length))
					pieceBuf[4] = pieceMsgID
					binary.BigEndian.PutUint32(pieceBuf[5:9], index)
					binary.BigEndian.PutUint32(pieceBuf[9:13], begin)
					rand.Read(pieceBuf[13:])
					conn.Write(pieceBuf)
				}
			}
		}
	}
}

type TorrentConn struct {
	net.Conn
	reader           *bufio.Reader
	writer           *bufio.Writer
	remainingPayload int
	remainingPadding int
	flushTimer       *time.Timer
	mu               sync.Mutex
	enc              cipher.Stream
	dec              cipher.Stream
}

func NewTorrentConn(conn net.Conn, authKey []byte, infoHash [20]byte, nonce []byte) *TorrentConn {
	tc := &TorrentConn{
		Conn:   conn,
		reader: bufio.NewReaderSize(conn, 256*1024),
	}
	key := sha256.Sum256(authKey)
	ivSeed := append(nonce, infoHash[:]...)
	iv := sha256.Sum256(ivSeed)
	block, err := aes.NewCipher(key[:])
	if err == nil {
		tc.enc = cipher.NewCTR(block, iv[16:32])
		tc.dec = cipher.NewCTR(block, iv[:16])
	}
	tc.writer = bufio.NewWriterSize(&rawPieceWriter{tc}, 16*1024)
	return tc
}

type rawPieceWriter struct{ tc *TorrentConn }

func (w *rawPieceWriter) Write(p []byte) (int, error) { return w.tc.writePiece(p) }

func (c *TorrentConn) Read(p []byte) (n int, err error) {
	for {
		if c.remainingPayload > 0 {
			toRead := c.remainingPayload
			if toRead > len(p) {
				toRead = len(p)
			}
			n, err = c.reader.Read(p[:toRead])
			if err != nil {
				return n, err
			}
			if c.dec != nil {
				c.dec.XORKeyStream(p[:n], p[:n])
			}
			c.remainingPayload -= n
			return n, nil
		}
		if c.remainingPadding > 0 {
			if _, err := c.reader.Discard(c.remainingPadding); err != nil {
				return 0, err
			}
			c.remainingPadding = 0
		}
		var header [4]byte
		if _, err := io.ReadFull(c.reader, header[:]); err != nil {
			return 0, err
		}
		length := binary.BigEndian.Uint32(header[:])
		if length == 0 {
			continue
		}
		msgID, err := c.reader.ReadByte()
		if err != nil {
			return 0, err
		}
		if msgID == pieceMsgID {
			if _, err := c.reader.Discard(8); err != nil {
				return 0, err
			}
			var pLenBuf [2]byte
			if _, err := io.ReadFull(c.reader, pLenBuf[:]); err != nil {
				return 0, err
			}
			pLen := int(binary.BigEndian.Uint16(pLenBuf[:]))
			totalInPiece := int(length) - 11
			if pLen > totalInPiece {
				return 0, fmt.Errorf("torrent protocol corruption")
			}
			c.remainingPayload = pLen
			c.remainingPadding = totalInPiece - pLen
			if c.remainingPayload == 0 {
				continue
			}
		} else {
			if _, err := c.reader.Discard(int(length) - 1); err != nil {
				return 0, err
			}
		}
	}
}

func (c *TorrentConn) Write(p []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, err = c.writer.Write(p)
	if c.flushTimer != nil {
		c.flushTimer.Stop()
	}
	c.flushTimer = time.AfterFunc(5*time.Millisecond, func() {
		c.mu.Lock()
		c.writer.Flush()
		c.mu.Unlock()
	})
	return n, err
}

func (c *TorrentConn) writePiece(p []byte) (n int, err error) {
	const internalHeadLen = 2
	padLen := mrand.Intn(256)
	bufPtr := udpBufPool.Get().(*[]byte)
	defer udpBufPool.Put(bufPtr)
	buf := *bufPtr
	totalMsgLen := 9 + internalHeadLen + len(p) + padLen
	binary.BigEndian.PutUint32(buf[0:4], uint32(totalMsgLen))
	buf[4] = pieceMsgID
	binary.BigEndian.PutUint32(buf[5:9], uint32(mrand.Int31n(1000)))
	binary.BigEndian.PutUint32(buf[9:13], uint32(mrand.Int31n(131072)))
	binary.BigEndian.PutUint16(buf[13:15], uint16(len(p)))
	if c.enc != nil {
		c.enc.XORKeyStream(buf[15:15+len(p)], p)
	} else {
		copy(buf[15:], p)
	}
	if padLen > 0 {
		rand.Read(buf[15+len(p) : 15+len(p)+padLen])
	}
	_, err = c.Conn.Write(buf[:4+totalMsgLen])
	return len(p), err
}
