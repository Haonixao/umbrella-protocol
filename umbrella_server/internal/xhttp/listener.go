package xhttp

import (
	"bufio"
	"io"
	"log"
	"net"
	"sync"
	"time"
	"umbrella_server/internal/activator"
)

// udpSession хранит состояние UDP-relay для одного клиента (IP:port).
type udpSession struct {
	clientAddr *net.UDPAddr
	backend    *net.UDPConn
}

type quicFrontend struct {
	conn        *net.UDPConn
	dest        string
	backend     string
	sessions    map[string]*udpSession
	sessionsMu  sync.RWMutex
	sessionWait map[string]chan struct{}
	waitMu      sync.Mutex
	ac          *activator.Activator
}

// bufferedConn позволяет "подсмотреть" данные и вернуть их обратно
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

type ipFilterListener struct {
	inner net.Listener
	dest  string
	mode  string
	ac    *activator.Activator
}

func (l *ipFilterListener) Close() error {
	return l.inner.Close()
}

func (l *ipFilterListener) Addr() net.Addr {
	return l.inner.Addr()
}

func (l *ipFilterListener) Accept() (net.Conn, error) {
	for {
		c, err := l.inner.Accept()
		if err != nil {
			return nil, err
		}
		host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
		br := bufio.NewReader(c)

		if l.ac.IsIpActivated(host) {
			log.Printf("[INFO] Valid client, forwarding → %s", host)
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

	if q.ac.IsIpActivated(clientIP) {
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
