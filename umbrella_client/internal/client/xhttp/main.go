package xhttp

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"strconv"
	"sync"
	"time"

	"umbrella_client/internal/client/bypass"
	"umbrella_client/internal/client/config"
	"umbrella_client/internal/client/shaper"
	"umbrella_client/internal/client/share"
)

var (
	cfg            *config.Config
	gServerAddr    string
	gAuthKey       []byte
	gListenAddr    string
	gBypass        []string
	gShaper        bool
	gXhttpClient   *Client
	gXhttpClientMu sync.Mutex
	tcpSessions    []*tcpSession
	tcpSessionsMu  sync.Mutex
)

type tcpSession struct {
	tcpConn net.Conn
}

func Start(c *config.Config, ctx context.Context, appFilesDir string) error {
	cfg = c
	gServerAddr = cfg.Server
	gListenAddr = cfg.ListenAddr
	gBypass = make([]string, len(cfg.Bypass))
	copy(gBypass, cfg.Bypass)
	isActivated.Store(false)

	var err error
	if cfg.Xhttp.AuthKey == "" {
		return fmt.Errorf("auth-key is required")
	}
	gAuthKey, err = hex.DecodeString(cfg.Xhttp.AuthKey)
	if err != nil || len(gAuthKey) != 32 {
		return fmt.Errorf("invalid auth-key: must be 64 hex chars (32 bytes)")
	}

	if host, _, err := net.SplitHostPort(gServerAddr); err == nil {
		gBypass = append(gBypass, host)
	} else {
		gBypass = append(gBypass, gServerAddr)
	}

	gBypass = append(
		gBypass,
		"127.0.0.0/8",
		"::1/128",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
		"fc00::/7",
		"fe80::/10",
	)

	gShaper = cfg.Shaper
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
		go func() {
			shaper.RunShaperEngine(ctx)
		}()
	}

	alpn := []string{"h2"}
	if cfg.Xhttp.Quic {
		alpn = []string{"h3"}
	}

	transport := NewTransport(gServerAddr, cfg.SNI, alpn, cfg.Xhttp.AuthKey)

	// 2. Создаем xhttp.Client
	gXhttpClient = &Client{
		ctx:       ctx,
		host:      cfg.SNI,
		path:      cfg.Xhttp.Path,
		authKey:   cfg.Xhttp.AuthKey,
		mode:      cfg.Xhttp.Mode, // stream-one, stream-up, packet-up
		transport: transport,
	}

	// Ротация
	go func() {
		for {
			// Рандомная задержка [30, 60) минут
			minDelay := 30 * time.Minute
			maxJitter := 30 * time.Minute

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

			newTransport := NewTransport(gServerAddr, cfg.SNI, alpn, cfg.Xhttp.AuthKey)
			newXhttpClient := &Client{
				ctx:       ctx,
				host:      cfg.SNI,
				path:      cfg.Xhttp.Path,
				authKey:   cfg.Xhttp.AuthKey,
				mode:      cfg.Xhttp.Mode, // stream-one, stream-up, packet-up
				transport: newTransport,
			}

			gXhttpClientMu.Lock()

			go func() {
				oldXhttpClient := gXhttpClient
				// Даем 5 минут времени чтобы горячие соединения успели сами закрыться
				select {
				case <-time.After(time.Minute * 5):
				case <-ctx.Done():
					return
				}
				oldXhttpClient.Close()
			}()

			gXhttpClient = newXhttpClient

			gXhttpClientMu.Unlock()
		}
	}()

	ln, err := net.Listen("tcp", gListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %v", cfg.ListenAddr, err)
	}
	defer ln.Close()

	log.Printf("[INFO] Umbrella/Xhttp client on %s (SOCKS5) → %s (SNI: %s)", cfg.ListenAddr, cfg.Server, cfg.SNI)

	for {
		select {
		case <-ctx.Done():
			log.Printf("[INFO] Umbrella/Xhttp client listener closed, stopping")
			go func() {
				// 1. Закрываем все активные прокси-сессии
				tcpSessionsMu.Lock()
				for _, s := range tcpSessions {
					if s.tcpConn != nil {
						s.tcpConn.Close()
					}
				}
				tcpSessions = nil
				tcpSessionsMu.Unlock()

				// 2. Закрываем основной клиент xhttp
				gXhttpClientMu.Lock()
				if gXhttpClient != nil {
					gXhttpClient.Close()
				}
				gXhttpClientMu.Unlock()

				isActivated.Store(false)
			}()
			return nil
		default:
		}

		conn, err := ln.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			log.Printf("[ERR] SOCKS5 accept: %v", err)
			continue
		}
		go handleSOCKS5(ctx, conn)
	}
}

func dial(target string, ctx context.Context, isUDP bool) (net.Conn, error) {
	gXhttpClientMu.Lock()
	client := gXhttpClient
	gXhttpClientMu.Unlock()

	// 1. Устанавливаем xhttp соединение (зашифрованный туннель)
	conn, err := client.Dial(ctx, isUDP)
	if err != nil {
		return nil, fmt.Errorf("xhttp dial failed: %w", err)
	}

	// 2. Формируем преамбулу: [1:cmd][1:atyp][host/ip][2:port]
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		conn.Close()
		return nil, err
	}
	port, _ := strconv.Atoi(portStr)

	// Байт команды: 0x01 для TCP, 0x03 для UDP (согласно SOCKS5)
	cmd := byte(0x01)
	if isUDP {
		cmd = 0x03
	}

	var atyp byte
	var hostBytes []byte
	ip := net.ParseIP(host)
	if ip == nil {
		atyp = 0x03 // Domain
		hostBytes = append([]byte{byte(len(host))}, []byte(host)...)
	} else if ip4 := ip.To4(); ip4 != nil {
		atyp = 0x01 // IPv4
		hostBytes = ip4
	} else {
		atyp = 0x04 // IPv6
		hostBytes = ip.To16()
	}

	// Собираем преамбулу [CMD][ATYP][HOST...][PORT]
	preamble := make([]byte, 0, 1+1+len(hostBytes)+2)
	preamble = append(preamble, cmd)
	preamble = append(preamble, atyp)
	preamble = append(preamble, hostBytes...)

	pBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(pBuf, uint16(port))
	preamble = append(preamble, pBuf...)

	// 3. Отправляем преамбулу.
	if _, err := conn.Write(preamble); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send preamble: %w", err)
	}

	// 4. Читаем байт подтверждения от сервера
	okBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, okBuf); err != nil {
		conn.Close()
		// Если сервер закрыл соединение без байта, это EOF
		return nil, fmt.Errorf("failed to read confirmation (EOF) %w", err)
	}

	// Если статус не 0x00, значит сервер не смог подключиться к цели
	if okBuf[0] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("server failed to connect to target (status 0x%02x)", okBuf[0])
	}

	return conn, nil
}

func handleSOCKS5(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	cmd, host, port, err := share.Socks5Handshake(conn, cfg.UDPEnabled)
	if err != nil {
		log.Printf("[ERR] SOCKS5 handshake error from %s: %v", conn.RemoteAddr(), err)
		return
	}

	if cmd == 0x03 {
		if err := handleSocks5UDP(ctx, conn); err != nil {
			log.Printf("[ERR] SOCKS5 UDP ASSOCIATE failed: %v", err)
		}
		return
	}

	var isShouldBypass bool
	isShouldBypass = bypass.ShouldBypass(host, gBypass)

	if isShouldBypass {
		_, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		if err != nil {
			log.Printf("[ERR] write: %v", err)
			return
		}
		share.HandleDirect(ctx, conn, host, port)
		return
	}

	_, err = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	if err != nil {
		log.Printf("[ERR] write: %v", err)
		return
	}

	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	log.Printf("[INFO] Tunneling %s → %s", conn.RemoteAddr(), target)

	xConn, err := dial(target, ctx, false)
	if err != nil {
		log.Printf("[ERR] tcp dial to %s → %v", target, err)
		return
	}

	// Регистрируем сессию
	sess := &tcpSession{tcpConn: xConn}
	tcpSessionsMu.Lock()
	tcpSessions = append(tcpSessions, sess)
	tcpSessionsMu.Unlock()

	defer func() {
		xConn.Close()
		// Удаляем из списка при завершении
		tcpSessionsMu.Lock()
		for i, s := range tcpSessions {
			if s == sess {
				tcpSessions = append(tcpSessions[:i], tcpSessions[i+1:]...)
				break
			}
		}
		tcpSessionsMu.Unlock()
	}()

	var uploadWriter io.Writer = xConn
	var downloadReader io.Reader = xConn
	if gShaper {
		uploadWriter = &shaper.ShapedWriter{W: xConn, Bucket: &shaper.GUpBucket}
		downloadReader = &shaper.ShapedReader{R: xConn, Bucket: &shaper.GDownBucket}
	}

	// Relay data with half-close support
	go func() {
		b := share.CopyBufPool.Get().(*[]byte)
		defer share.CopyBufPool.Put(b)
		_, err := io.CopyBuffer(uploadWriter, conn, *b)
		if err != nil {
			// log.Printf("[ERR] copy: %v", err)
			return
		}
		share.CloseWrite(xConn)
	}()

	b := share.CopyBufPool.Get().(*[]byte)
	_, err = io.CopyBuffer(conn, downloadReader, *b)
	if err != nil {
		// log.Printf("[ERR] copy: %v", err)
		return
	}
	share.CopyBufPool.Put(b)
}

// parseSOCKS5UDPAddr parses the destination address from a SOCKS5 UDP datagram.
// Returns the host, port, and the starting index of the actual data.
func parseSOCKS5UDPAddr(buf []byte) (host string, port uint16, dataStart int, err error) {
	if len(buf) < 4 {
		return "", 0, 0, fmt.Errorf("packet too short")
	}
	// buf[0:2] RSV, buf[2] FRAG
	atyp := buf[3]
	switch atyp {
	case 0x01: // IPv4
		if len(buf) < 10 {
			return "", 0, 0, fmt.Errorf("short IPv4 packet")
		}
		host = net.IP(buf[4:8]).String()
		port = binary.BigEndian.Uint16(buf[8:10])
		dataStart = 10
	case 0x03: // Domain
		hostLen := int(buf[4])
		if len(buf) < 5+hostLen+2 {
			return "", 0, 0, fmt.Errorf("short domain packet")
		}
		host = string(buf[5 : 5+hostLen])
		port = binary.BigEndian.Uint16(buf[5+hostLen : 5+hostLen+2])
		dataStart = 5 + hostLen + 2
	case 0x04: // IPv6
		if len(buf) < 22 {
			return "", 0, 0, fmt.Errorf("short IPv6 packet")
		}
		host = net.IP(buf[4:20]).String()
		port = binary.BigEndian.Uint16(buf[20:22])
		dataStart = 22
	default:
		return "", 0, 0, fmt.Errorf("unknown address type %d", atyp)
	}
	return host, port, dataStart, nil
}

type xhttpUdpSession struct {
	conn       net.Conn
	lastActive time.Time
}

func handleSocks5UDP(ctx context.Context, tcpConn net.Conn) error {
	udpConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		tcpConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return err
	}
	defer udpConn.Close()

	udpAddr := udpConn.LocalAddr().(*net.UDPAddr)
	reply := []byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, byte(udpAddr.Port >> 8), byte(udpAddr.Port)}
	_, err = tcpConn.Write(reply)
	if err != nil {
		log.Printf("[ERR] write: %v", err)
		return err
	}

	log.Printf("[INFO] UDP relay active, local UDP: %s", udpAddr)

	var (
		addrMu      sync.Mutex
		appAddr     net.Addr
		sessions    = make(map[string]*xhttpUdpSession)
		sessionsMu  sync.Mutex
		sessionWait = make(map[string]chan struct{})
	)

	removeSession := func(target string) {
		sessionsMu.Lock()
		if sess, ok := sessions[target]; ok {
			sess.conn.Close()
			delete(sessions, target)
			log.Printf("[INFO] UDP session for %s removed due to error/timeout", target)
		}
		sessionsMu.Unlock()
	}

	// Session cleanup worker
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				sessionsMu.Lock()
				for target, sess := range sessions {
					if time.Since(sess.lastActive) > 60*time.Second {
						log.Printf("[INFO] Closing idle UDP session for %s", target)
						sess.conn.Close()
						delete(sessions, target)
					}
				}
				sessionsMu.Unlock()
			}
		}
	}()

	// App → Server (Uplink)
	go func() {
		// Берем буфер из пула
		bufPtr := share.UDPBufPool.Get().(*[]byte)
		defer share.UDPBufPool.Put(bufPtr)
		buf := *bufPtr

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			n, addr, err := udpConn.ReadFrom(buf)
			if err != nil {
				// log.Printf("[ERR] failed udp: %v", err)
				return
			}

			addrMu.Lock()
			if appAddr == nil {
				appAddr = addr
			}
			isApp := addr.String() == appAddr.String()
			addrMu.Unlock()

			if !isApp {
				// Прямой ответ от bypassed хоста (Direct Bypass)
				handleDirectUDPResponse(udpConn, addr, buf[:n], appAddr)
				continue
			}

			// Пакет от приложения. Проверяем SOCKS5 заголовок.
			if n < 4 || buf[2] != 0x00 {
				continue
			}
			host, port, dataStart, err := parseSOCKS5UDPAddr(buf)
			if err != nil {
				log.Printf("[ERR] failed parse: %v", err)
				return
			}
			targetAddr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

			if bypass.ShouldBypass(host, gBypass) {
				tAddr, err := net.ResolveUDPAddr("udp", targetAddr)
				if err != nil {
					log.Printf("[ERR] failed resolve: %v", err)
					return
				}
				_, err = udpConn.WriteTo(buf[dataStart:n], tAddr)
				if err != nil {
					log.Printf("[ERR] failed write: %v", err)
					return
				}
				continue
			}

			// Работа через туннель xhttp
			sessionsMu.Lock()
			sess, ok := sessions[targetAddr]
			if ok {
				sess.lastActive = time.Now()
				_, err := sess.conn.Write(buf[dataStart:n])
				sessionsMu.Unlock() // Разблокируем сразу после записи

				if err != nil {
					log.Printf("[ERR] UDP Uplink error for %s: %v", targetAddr, err)
					removeSession(targetAddr) // УДАЛЯЕМ при ошибке записи
				}
				continue
			}
			sessionsMu.Unlock()

			sessionsMu.Lock()
			// Создание новой сессии (с ожиданием, чтобы не дублировать)
			waitCh, busy := sessionWait[targetAddr]
			if busy {
				sessionsMu.Unlock()
				<-waitCh
				// Пакет проснулся, теперь сессия точно есть в sessions.
				// Нужно снова залочиться и отправить текущие данные.
				sessionsMu.Lock()
				if sess, ok := sessions[targetAddr]; ok {
					sess.lastActive = time.Now()
					sess.conn.Write(buf[dataStart:n])
				}
				sessionsMu.Unlock()
				continue
			}
			waitCh = make(chan struct{})
			sessionWait[targetAddr] = waitCh
			sessionsMu.Unlock()

			// Запускаем асинхронный Dial
			go func(data []byte, target string, sender net.Addr) {
				defer func() {
					sessionsMu.Lock()
					delete(sessionWait, target)
					close(waitCh)
					sessionsMu.Unlock()
				}()

				tunnelConn, err := dial(target, ctx, true)
				if err != nil {
					log.Printf("[ERR] udp dial to %s → %v", target, err)
					return
				}

				_, err = tunnelConn.Write(data)
				if err != nil {
					log.Printf("[ERR] failed write: %v", err)
					return
				}

				newSess := &xhttpUdpSession{
					conn:       tunnelConn,
					lastActive: time.Now(),
				}

				sessionsMu.Lock()
				sessions[target] = newSess
				sessionsMu.Unlock()

				// Server → App (Downlink)
				go func() {
					targetForCleanup := target            // Замыкаем target
					defer removeSession(targetForCleanup) // ГАРАНТИРОВАННО удаляем при выходе
					defer tunnelConn.Close()
					// Используем свой буфер для чтения из туннеля
					respBufPtr := share.UDPBufPool.Get().(*[]byte)
					defer share.UDPBufPool.Put(respBufPtr)
					respBuf := *respBufPtr

					// Максимальный заголовок SOCKS5 (Domain) ~ 262 байта.
					// Читаем данные с запасом, например с 300-го байта.
					dataOffset := 300

					for {
						// Устанавливаем таймаут на чтение из туннеля
						tunnelConn.SetReadDeadline(time.Now().Add(70 * time.Second))

						rn, err := tunnelConn.Read(respBuf[dataOffset:])
						if err != nil {
							if err != io.EOF {
								log.Printf("[ERR] UDP Downlink read error from %s: %v", targetForCleanup, err)
							}
							return // Выход приведет к вызову defer removeSession
						}

						// Собираем SOCKS5 UDP ответ прямо в этом же буфере
						// RSV(2) + FRAG(1) + ATYP(1) + ADDR(4/16) + PORT(2)
						headerLen, err := buildSocks5UDPHeader(respBuf[0:dataOffset], target)
						if err != nil {
							log.Printf("[ERR] failed build socks header: %v", err)
							return
						}

						// Копируем заголовок вплотную к данным
						// headerStart — это место, откуда начнется итоговый пакет
						headerStart := dataOffset - headerLen
						copy(respBuf[headerStart:dataOffset], respBuf[0:headerLen])

						// Отправляем: [заголовок][данные]
						_, err = udpConn.WriteTo(respBuf[headerStart:dataOffset+rn], sender)
						if err != nil {
							log.Printf("[ERR] failed write: %v", err)
							return
						}

						// Обновляем время активности, чтобы cleanup worker не закрыл сессию раньше времени
						sessionsMu.Lock()
						if s, ok := sessions[targetForCleanup]; ok {
							s.lastActive = time.Now()
						}
						sessionsMu.Unlock()
					}
				}()
			}(append([]byte(nil), buf[dataStart:n]...), targetAddr, addr)
		}
	}()

	_, err = io.Copy(io.Discard, tcpConn)
	return err
}

// Помощник для прямого ответа (Bypass)
func handleDirectUDPResponse(udpConn net.PacketConn, from net.Addr, data []byte, app net.Addr) {
	if app == nil {
		return
	}
	udpSrc := from.(*net.UDPAddr)

	respPtr := share.UDPBufPool.Get().(*[]byte)
	defer share.UDPBufPool.Put(respPtr)
	resp := *respPtr

	resp[0], resp[1], resp[2] = 0, 0, 0
	headerLen := 3
	if ip4 := udpSrc.IP.To4(); ip4 != nil {
		resp[3] = 0x01
		copy(resp[4:8], ip4)
		headerLen += 5
	} else {
		resp[3] = 0x04
		copy(resp[4:20], udpSrc.IP.To16())
		headerLen += 17
	}
	binary.BigEndian.PutUint16(resp[headerLen:headerLen+2], uint16(udpSrc.Port))
	headerLen += 2

	copy(resp[headerLen:], data)
	_, err := udpConn.WriteTo(resp[:headerLen+len(data)], app)
	if err != nil {
		log.Printf("[ERR] write: %v", err)
		return
	}
}

// Помощник для сборки заголовка в существующий буфер (пишет ПЕРЕД данными)
func buildSocks5UDPHeader(buf []byte, target string) (int, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return 0, err
	}
	port, _ := strconv.Atoi(portStr)
	ip := net.ParseIP(host)

	// RSV(2) + FRAG(1)
	buf[0], buf[1], buf[2] = 0, 0, 0

	var curr int
	if ip == nil {
		// ATYP: Domain
		buf[3] = 0x03
		buf[4] = byte(len(host))
		copy(buf[5:], host)
		curr = 5 + len(host)
	} else if ip4 := ip.To4(); ip4 != nil {
		// ATYP: IPv4
		buf[3] = 0x01
		copy(buf[4:8], ip4)
		curr = 8
	} else {
		// ATYP: IPv6
		buf[3] = 0x04
		copy(buf[4:20], ip.To16())
		curr = 20
	}

	// Port (2 bytes, BigEndian)
	binary.BigEndian.PutUint16(buf[curr:], uint16(port))
	return curr + 2, nil
}
