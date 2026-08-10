package torrent

import (
	"bufio"
	"context"
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
	"math/big"
	mrand "math/rand"
	"net"
	_ "net/http/pprof"
	"strconv"
	"strings"
	"sync"
	"time"

	"umbrella_client/internal/client/bypass"
	"umbrella_client/internal/client/config"
	"umbrella_client/internal/client/shaper"
	"umbrella_client/internal/client/share"

	"github.com/anacrolix/utp"
	"github.com/hashicorp/yamux"
)

const (
	pstr         = "BitTorrent protocol"
	pstrlen      = 19
	handshakeLen = 68
	pieceMsgID   = 7
	unchokeMsgID = 1
	interestedID = 2
	bitfieldID   = 5
	requestID    = 6
)

var (
	cfg                 *config.Config
	gServerAddr         string
	gAuthKey            []byte
	gInfoHash           [20]byte
	gBypass             []string
	gShaper             bool
	gSessionsNum        int
	gConnectionsTimeOut time.Duration

	// Session pool
	sessions     []*yamux.Session
	sessMu       []sync.Mutex
	getSessionMu sync.Mutex
)

func Start(c *config.Config, ctx context.Context, appFilesDir string) error {
	cfg = c
	gServerAddr = cfg.Server
	gShaper = cfg.Shaper
	gConnectionsTimeOut = time.Duration(cfg.Torrent.ConnectionsTimeOut) * time.Second
	gBypass = make([]string, len(cfg.Bypass))
	copy(gBypass, cfg.Bypass)

	gSessionsNum = cfg.Torrent.SessionsNum
	sessions = make([]*yamux.Session, gSessionsNum)
	sessMu = make([]sync.Mutex, gSessionsNum)

	var err error
	if cfg.Torrent.AuthKey == "" {
		return fmt.Errorf("auth-key is required for torrent protocol")
	}
	gAuthKey, err = hex.DecodeString(cfg.Torrent.AuthKey)
	if err != nil || len(gAuthKey) != 32 {
		return fmt.Errorf("invalid auth-key: must be 64 hex chars (32 bytes)")
	}

	if cfg.Torrent.InfoHash != "" {
		ih, err := hex.DecodeString(cfg.Torrent.InfoHash)
		if err != nil || len(ih) != 20 {
			return fmt.Errorf("invalid info-hash: must be 40 hex chars (20 bytes)")
		}
		copy(gInfoHash[:], ih)
	} else {
		rand.Read(gInfoHash[:])
		log.Printf("[INFO] Using random info-hash: %s", hex.EncodeToString(gInfoHash[:]))
	}

	serverHost, _, err := net.SplitHostPort(gServerAddr)
	if err != nil {
		serverHost = gServerAddr
	}
	gBypass = append(gBypass, serverHost, "127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "fc00::/7", "fe80::/10")

	if gShaper {
		if cfg.PhasesData != nil {
			if err := shaper.ParsePhases(cfg.PhasesData); err != nil {
				return fmt.Errorf("failed to parse embedded phases: %v", err)
			}
			log.Printf("[INFO] Loaded %d phases from embedded data", len(shaper.Phases))
		} else {
			if err := shaper.LoadPhases(cfg.PhasesFile); err != nil {
				return fmt.Errorf("failed to load phases from %s: %v", cfg.PhasesFile, err)
			}
			log.Printf("[INFO] Loaded %d phases from %s", len(shaper.Phases), cfg.PhasesFile)
		}
		go shaper.RunShaperEngine(ctx)
	}

	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %v", cfg.ListenAddr, err)
	}
	defer ln.Close()

	log.Printf("[INFO] Umbrella/Torrent client (uTP) on %s → %s", cfg.ListenAddr, cfg.Server)

	for {
		select {
		case <-ctx.Done():
			log.Printf("[INFO] Umbrella/Torrent client listener closed, stopping")
			return nil
		default:
		}
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[ERR] SOCKS5 accept: %v", err)
			continue
		}
		go handleSOCKS5(ctx, conn)
	}
}

func handleSOCKS5(ctx context.Context, conn net.Conn) {
	sCtx, sCancel := context.WithCancel(ctx)
	defer sCancel()
	defer conn.Close()

	conn = &timeoutConn{Conn: conn}
	cmd, host, port, err := share.Socks5Handshake(conn, cfg.UDPEnabled)
	if err != nil {
		log.Printf("[ERR] SOCKS5 handshake error from %s: %v", conn.RemoteAddr(), err)
		return
	}

	if cmd == 0x03 {
		handleSocks5UDP(ctx, conn)
		return
	}

	if bypass.ShouldBypass(host, gBypass) {
		conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		share.HandleDirect(sCtx, conn, host, port)
		return
	}

	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	log.Printf("[INFO] Tunneling %s → %s", conn.RemoteAddr(), target)

	var rawStream net.Conn
	var sErr error
	for attempt := 0; attempt < 3; attempt++ {
		sess, err := getSession(sCtx)
		if err != nil {
			log.Printf("[ERR] failed to get session: %v", err)
			return
		}
		rawStream, sErr = sess.Open()
		if sErr == nil {
			targetBytes := []byte(target)
			lenBuf := make([]byte, 4)
			binary.BigEndian.PutUint32(lenBuf, uint32(len(targetBytes)))
			if _, err := rawStream.Write(lenBuf); err == nil {
				if _, err := rawStream.Write(targetBytes); err == nil {
					break
				}
			}
			rawStream.Close()
			dropSession(sess)
		}
	}

	if sErr != nil || rawStream == nil {
		return
	}
	stream := &timeoutConn{Conn: rawStream}
	defer stream.Close()

	go func() {
		b := share.CopyBufPool.Get().(*[]byte)
		defer share.CopyBufPool.Put(b)
		var dst io.Writer = stream
		if gShaper {
			dst = &shaper.ShapedWriter{W: stream, Bucket: &shaper.GUpBucket}
		}
		io.CopyBuffer(dst, conn, *b)
		share.CloseWrite(stream)
	}()

	go func() {
		defer sCancel()
		b := share.CopyBufPool.Get().(*[]byte)
		defer share.CopyBufPool.Put(b)
		var src io.Reader = stream
		if gShaper {
			src = &shaper.ShapedReader{R: stream, Bucket: &shaper.GDownBucket}
		}
		io.CopyBuffer(conn, src, *b)
	}()

	<-sCtx.Done()
}

func handleSocks5UDP(ctx context.Context, rawTcpConn net.Conn) {
	rawUdpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		rawTcpConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		log.Printf("[ERR] UDP ASSOCIATE listen error: %v", err)
		return
	}
	udpConn := &timeoutPacketConn{PacketConn: rawUdpConn}
	udpCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer udpConn.Close()

	udpAddr := udpConn.LocalAddr().(*net.UDPAddr)
	reply := []byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, byte(udpAddr.Port >> 8), byte(udpAddr.Port)}
	if _, err := rawTcpConn.Write(reply); err != nil {
		return
	}

	var addrMu sync.Mutex
	var appAddr net.Addr
	var rawStream net.Conn
	for attempt := 0; attempt < 3; attempt++ {
		sess, err := getSession(udpCtx)
		if err != nil {
			log.Printf("[ERR] failed to get session for UDP: %v", err)
			return
		}
		s, err := sess.Open()
		if err == nil {
			targetBytes := []byte("UDP_RELAY")
			lenBuf := make([]byte, 4)
			binary.BigEndian.PutUint32(lenBuf, uint32(len(targetBytes)))
			if _, err := s.Write(lenBuf); err == nil {
				if _, err := s.Write(targetBytes); err == nil {
					rawStream = s
					break
				}
			}
			s.Close()
			dropSession(sess)
		}
	}
	if rawStream == nil {
		log.Printf("[ERR] failed to establish UDP stream after retries")
		return
	}
	stream := &timeoutConn{Conn: rawStream}
	defer stream.Close()

	var relayWriter io.Writer = stream
	var relayReader io.Reader = stream
	if gShaper {
		relayWriter = &shaper.ShapedWriter{W: stream, Bucket: &shaper.GUpBucket}
		relayReader = &shaper.ShapedReader{R: stream, Bucket: &shaper.GDownBucket}
	}

	log.Printf("[INFO] UDP relay active, local UDP: %s", udpAddr)

	// App -> Server / Bypass
	go func() {
		defer cancel()
		bufPtr := share.UDPBufPool.Get().(*[]byte)
		defer share.UDPBufPool.Put(bufPtr)
		buf := *bufPtr
		frameBufPtr := share.UDPBufPool.Get().(*[]byte)
		defer share.UDPBufPool.Put(frameBufPtr)
		frameBuf := *frameBufPtr

		for {
			n, addr, err := udpConn.ReadFrom(buf)
			if err != nil {
				return
			}
			addrMu.Lock()
			if appAddr == nil {
				appAddr = addr
			}
			isApp := addr.String() == appAddr.String()
			addrMu.Unlock()

			if !isApp {
				addrMu.Lock()
				app := appAddr
				addrMu.Unlock()
				if app != nil {
					udpSrc := addr.(*net.UDPAddr)
					resp := []byte{0, 0, 0}
					if ip4 := udpSrc.IP.To4(); ip4 != nil {
						resp = append(resp, 0x01)
						resp = append(resp, ip4...)
					} else {
						resp = append(resp, 0x04)
						resp = append(resp, udpSrc.IP.To16()...)
					}
					var p [2]byte
					binary.BigEndian.PutUint16(p[:], uint16(udpSrc.Port))
					resp = append(resp, p[:]...)
					resp = append(resp, buf[:n]...)
					udpConn.WriteTo(resp, app)
				}
				continue
			}

			if n < 4 || buf[2] != 0x00 {
				continue
			}

			host, port, dataStart, err := parseSOCKS5UDPAddr(buf)
			if err != nil {
				continue
			}

			isShouldBypass := bypass.ShouldBypass(host, gBypass)

			if isShouldBypass {
				targetAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
				if err == nil {
					udpConn.WriteTo(buf[dataStart:n], targetAddr)
				}
				continue
			}

			payload := buf[3:n]
			binary.BigEndian.PutUint32(frameBuf[:4], uint32(len(payload)))
			copy(frameBuf[4:], payload)
			relayWriter.Write(frameBuf[:4+len(payload)])
		}
	}()

	go func() {
		defer cancel()
		lenBuf := make([]byte, 4)
		pktBufPtr := share.UDPBufPool.Get().(*[]byte)
		defer share.UDPBufPool.Put(pktBufPtr)
		pktBuf := *pktBufPtr
		pktBuf[0], pktBuf[1], pktBuf[2] = 0, 0, 0
		for {
			if _, err := io.ReadFull(relayReader, lenBuf); err != nil {
				return
			}
			payloadLen := binary.BigEndian.Uint32(lenBuf)
			if payloadLen > 65535 {
				return
			}
			if _, err := io.ReadFull(relayReader, pktBuf[3:3+payloadLen]); err != nil {
				return
			}
			addrMu.Lock()
			a := appAddr
			addrMu.Unlock()
			if a != nil {
				udpConn.WriteTo(pktBuf[:3+payloadLen], a)
			}
		}
	}()
	<-udpCtx.Done()
}

func getSession(ctx context.Context) (*yamux.Session, error) {
	getSessionMu.Lock()
	defer getSessionMu.Unlock()
	idx := mrand.Intn(gSessionsNum)
	if sessions[idx] != nil && !sessions[idx].IsClosed() {
		return sessions[idx], nil
	}
	sess, err := establishSession(ctx, idx)
	if err == nil {
		return sess, nil
	}
	for i := 0; i < gSessionsNum; i++ {
		if sessions[i] != nil && !sessions[i].IsClosed() {
			return sessions[i], nil
		}
	}

	return nil, fmt.Errorf("no available sessions: %w", err)
}

func establishSession(ctx context.Context, idx int) (*yamux.Session, error) {
	sessMu[idx].Lock()
	defer sessMu[idx].Unlock()
	if sessions[idx] != nil && !sessions[idx].IsClosed() {
		return sessions[idx], nil
	}

	// Resolve server address and handle port hopping
	host, portStr, err := net.SplitHostPort(gServerAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid server address: %w", err)
	}

	var targetAddr string
	if strings.Contains(portStr, "-") {
		parts := strings.Split(portStr, "-")
		start, _ := strconv.Atoi(parts[0])
		end, _ := strconv.Atoi(parts[1])
		targetAddr = net.JoinHostPort(host, strconv.Itoa(start+mrand.Intn(end-start+1)))
	} else {
		targetAddr = gServerAddr
	}

	s, err := utp.Dial(targetAddr)
	if err != nil {
		return nil, err
	}

	peerID, nonce := generatePeerID()
	handshake := make([]byte, handshakeLen)
	handshake[0] = pstrlen
	copy(handshake[1:20], pstr)
	copy(handshake[28:48], gInfoHash[:])
	copy(handshake[48:68], peerID[:])

	if _, err := s.Write(handshake); err != nil {
		s.Close()
		return nil, err
	}

	// 3. Receive server handshake
	s.SetReadDeadline(time.Now().Add(30 * time.Second))
	respHandshake := make([]byte, handshakeLen)
	if _, err := io.ReadFull(s, respHandshake); err != nil {
		s.Close()
		return nil, err
	}
	s.SetReadDeadline(time.Time{})

	s.Write([]byte{0, 0, 0, 1, interestedID})
	s.Write([]byte{0, 0, 0, 1, unchokeMsgID})

	muxCfg := yamux.DefaultConfig()
	muxCfg.MaxStreamWindowSize = 8 * 1024 * 1024
	muxCfg.EnableKeepAlive = true
	muxCfg.StreamCloseTimeout = 10 * time.Second
	muxCfg.LogOutput = io.Discard

	sess, err := yamux.Client(NewTorrentConn(s, gAuthKey, gInfoHash, nonce), muxCfg)
	if err != nil {
		s.Close()
		return nil, err
	}
	go scheduleReconnect(ctx, sess)
	sessions[idx] = sess
	return sess, nil
}

func scheduleReconnect(ctx context.Context, s *yamux.Session) {
	const minDelay = 30 * time.Minute
	const maxJitter = 30 * time.Minute
	delay := minDelay
	n, err := rand.Int(rand.Reader, big.NewInt(int64(maxJitter)))
	if err == nil {
		delay += time.Duration(n.Int64())
	}

	select {
	case <-time.After(delay):
	case <-ctx.Done():
		return
	}

	for i := 0; i < gSessionsNum; i++ {
		sessMu[i].Lock()
		if sessions[i] == s {
			sessions[i] = nil
			go func() {
				time.Sleep(5 * time.Minute)
				s.Close()
			}()
			sessMu[i].Unlock()
			break
		}
		sessMu[i].Unlock()
	}
}

func dropSession(s *yamux.Session) {
	for i := 0; i < gSessionsNum; i++ {
		sessMu[i].Lock()
		if sessions[i] == s {
			sessions[i] = nil
			go s.Close()
			sessMu[i].Unlock()
			break
		}
		sessMu[i].Unlock()
	}
}

func generatePeerID() ([20]byte, []byte) {
	var pid [20]byte
	copy(pid[:8], []byte("-TR4000-"))

	// 1. Генерируем 5 случайных байт (как в вашем TLS примере)
	// Но так как места мало, возьмем 4 байта
	rnd := make([]byte, 4)
	rand.Read(rnd)

	// 2. Получаем минуты с начала года (3 байта)
	now := time.Now().UTC()
	yearStart := time.Date(now.Year(), 1, 1, 0, 0, 0, 0, time.UTC)
	minutes := uint32(now.Sub(yearStart).Minutes())
	minBytes := make([]byte, 3)
	minBytes[0] = byte(minutes >> 16)
	minBytes[1] = byte(minutes >> 8)
	minBytes[2] = byte(minutes)

	// 3. Зашумляем время через XOR с частью rnd
	maskedTime := make([]byte, 3)
	for i := 0; i < 3; i++ {
		maskedTime[i] = minBytes[i] ^ rnd[i]
	}

	// Собираем: [Prefix:8][Rnd:4][MaskedTime:3][HMAC:5]
	copy(pid[8:12], rnd)
	copy(pid[12:15], maskedTime)

	// 4. Подпись HMAC от Rnd + Real Minutes + InfoHash
	mac := hmac.New(sha1.New, gAuthKey)
	mac.Write(rnd)
	mac.Write(minBytes)
	mac.Write(gInfoHash[:])
	sig := mac.Sum(nil)[:5]
	copy(pid[15:20], sig)

	return pid, rnd // Возвращаем rnd как nonce для AES
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

	// Initialize AES-CTR for light payload encryption
	// Key = SHA256(AuthKey)
	// IV = SHA256(nonce + InfoHash)[:16]
	key := sha256.Sum256(authKey)
	ivSeed := append(nonce, infoHash[:]...)
	iv := sha256.Sum256(ivSeed)

	block, err := aes.NewCipher(key[:])
	if err == nil {
		tc.enc = cipher.NewCTR(block, iv[:16])
		tc.dec = cipher.NewCTR(block, iv[16:32]) // Use second half of SHA256 for symmetry
	}

	// Оборачиваем запись в буфер для снижения оверхеда паддинга
	tc.writer = bufio.NewWriterSize(&rawPieceWriter{tc}, 16*1024)
	return tc
}

type rawPieceWriter struct{ tc *TorrentConn }

func (w *rawPieceWriter) Write(p []byte) (int, error) { return w.tc.writePiece(p) }

func (c *TorrentConn) Read(p []byte) (n int, err error) {
	if c.reader == nil {
		c.reader = bufio.NewReaderSize(c.Conn, 256*1024)
	}
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
		var h [4]byte
		if _, err := io.ReadFull(c.reader, h[:]); err != nil {
			return 0, err
		}
		length := binary.BigEndian.Uint32(h[:])
		if length == 0 {
			continue
		}

		// Читаем ID (1 байт)
		msgID, err := c.reader.ReadByte()
		if err != nil {
			return 0, err
		}

		if msgID == pieceMsgID {
			// Discard Index(4) + Offset(4) = 8 bytes
			if _, err := c.reader.Discard(8); err != nil {
				return 0, err
			}

			// Читаем наш внутренний заголовок PayloadLen (2 байта)
			var pLenBuf [2]byte
			if _, err := io.ReadFull(c.reader, pLenBuf[:]); err != nil {
				return 0, err
			}
			pLen := int(binary.BigEndian.Uint16(pLenBuf[:]))

			// Общий остаток в этом piece (за вычетом Index+Offset+PayloadLen)
			totalInPiece := int(length) - 11
			if pLen > totalInPiece {
				return 0, fmt.Errorf("torrent protocol corruption: payload %d > total %d", pLen, totalInPiece)
			}

			c.remainingPayload = pLen
			c.remainingPadding = totalInPiece - pLen

			if c.remainingPayload == 0 {
				continue
			}
		} else {
			// Пропускаем другие типы сообщений
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
	const bittorrentHeadLen = 9
	const internalHeadLen = 2
	padLen := mrand.Intn(256)
	bufPtr := share.UDPBufPool.Get().(*[]byte)
	defer share.UDPBufPool.Put(bufPtr)
	buf := *bufPtr

	totalMsgLen := bittorrentHeadLen + internalHeadLen + len(p) + padLen
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

func parseSOCKS5UDPAddr(buf []byte) (host string, port uint16, dataStart int, err error) {
	if len(buf) < 4 {
		return "", 0, 0, fmt.Errorf("short")
	}
	atyp := buf[3]
	switch atyp {
	case 0x01:
		host = net.IP(buf[4:8]).String()
		port = binary.BigEndian.Uint16(buf[8:10])
		dataStart = 10
	case 0x03:
		l := int(buf[4])
		host = string(buf[5 : 5+l])
		port = binary.BigEndian.Uint16(buf[5+l : 5+l+2])
		dataStart = 5 + l + 2
	case 0x04:
		host = net.IP(buf[4:20]).String()
		port = binary.BigEndian.Uint16(buf[20:22])
		dataStart = 22
	}
	return host, port, dataStart, nil
}

type timeoutConn struct{ net.Conn }

func (ts *timeoutConn) Read(p []byte) (n int, err error) {
	if gConnectionsTimeOut > 0 {
		ts.Conn.SetReadDeadline(time.Now().Add(gConnectionsTimeOut))
	}
	return ts.Conn.Read(p)
}

func (ts *timeoutConn) Write(p []byte) (n int, err error) {
	if gConnectionsTimeOut > 0 {
		ts.Conn.SetWriteDeadline(time.Now().Add(gConnectionsTimeOut))
	}
	return ts.Conn.Write(p)
}

func (ts *timeoutConn) CloseWrite() error {
	if hc, ok := ts.Conn.(interface{ CloseWrite() error }); ok {
		return hc.CloseWrite()
	}
	return nil
}

type timeoutPacketConn struct{ net.PacketConn }

func (ts *timeoutPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if gConnectionsTimeOut > 0 {
		ts.PacketConn.SetReadDeadline(time.Now().Add(gConnectionsTimeOut))
	}
	return ts.PacketConn.ReadFrom(p)
}

func (ts *timeoutPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if gConnectionsTimeOut > 0 {
		ts.PacketConn.SetWriteDeadline(time.Now().Add(gConnectionsTimeOut))
	}
	return ts.PacketConn.WriteTo(p, addr)
}
