package hysteria

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"log"
	"math/big"
	"net"
	"sync"
	"time"

	"umbrella_server/internal/activator"
	"umbrella_server/internal/config"
	"umbrella_server/pkg/ip"

	"github.com/apernet/hysteria/core/v2/server"
	"github.com/apernet/hysteria/extras/v2/auth"
)

type session struct {
	clientAddr *net.UDPAddr
	backend    *net.UDPConn
}

var (
	cfg         *config.Config
	sessions    = make(map[string]*session)
	sessionsMu  sync.RWMutex
	frontendLn  *net.UDPConn
	hysteriaSrv server.Server
	cachedCert  *tls.Certificate
	certOnce    sync.Once
	quicPort    = "8443"
)

func HysteriaStarter(c *config.Config) {
	cfg = c

	if cfg.Hysteria.AuthPassword == "" {
		cfg.Hysteria.AuthPassword = generatePassword()
		log.Printf("[INFO] Generated auth-password — save this for client")
	}

	log.Printf("[INFO] Auth password: %s", cfg.Hysteria.AuthPassword)

	serverIp, err := ip.CheckIp()
	if err != nil {
		log.Fatalf("[ERR] ip check error: %v", err)
	}

	sni, _, err := net.SplitHostPort(cfg.Dest)
	if err != nil {
		log.Fatalf("[ERR] get sni from dest: %v", err)
	}

	clientCfg := config.ClientConfig{
		Protocol: cfg.Protocol,
		Server:   serverIp + ":" + cfg.Port,
		SNI:      sni,
		Hysteria: struct {
			AuthPassword string "yaml:\"auth-password\""
		}{
			AuthPassword: cfg.Hysteria.AuthPassword,
		},
	}

	ac, err := activator.SetupActivator(*cfg, clientCfg)
	if err != nil {
		log.Fatalf("[ERR] setup activator: %v", err)
	}

	go startHysteriaServer()

	log.Printf("[INFO] Umbrella/Hysteria server on :%s (fallback → %s)", cfg.Port, cfg.Dest)

	startFrontend(ac)
}

func startHysteriaServer() {
	addr, err := net.ResolveUDPAddr("udp", ":"+quicPort)
	if err != nil {
		log.Fatalf("[ERR] resolve hysteria addr: %v", err)
	}

	ln, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("[ERR] listen UDP on :%s: %v", quicPort, err)
	}
	defer ln.Close()

	if err := ln.SetWriteBuffer(4 * 1024 * 1024); err != nil {
		log.Printf("[ERR] Failed to set UDP write buffer: %v", err)
	}

	var certErr error
	certOnce.Do(func() {
		cachedCert, certErr = generateSelfSignedCert()
	})
	if certErr != nil {
		log.Fatalf("[ERR] generate cert: %v", certErr)
	}

	srv, err := server.NewServer(&server.Config{
		Conn: ln,
		TLSConfig: server.TLSConfig{
			GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
				return cachedCert, nil
			},
		},
		Authenticator:  &auth.PasswordAuthenticator{Password: cfg.Hysteria.AuthPassword},
		DisableUDP:     false,
		UDPIdleTimeout: 120 * time.Second,
	})
	if err != nil {
		log.Fatalf("[ERR] create hysteria server: %v", err)
	}

	hysteriaSrv = srv

	if err := srv.Serve(); err != nil {
		log.Printf("[ERR] hysteria serve: %v", err)
	}
}

func generateSelfSignedCert() (*tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Hysteria Server"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour * 365),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	return &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}, nil
}

func generatePassword() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("[ERR] generate password: %v", err)
	}
	return hex.EncodeToString(b)
}

func startFrontend(ac *activator.Activator) {
	addr, err := net.ResolveUDPAddr("udp", ":"+cfg.Port)
	if err != nil {
		log.Fatalf("[ERR] resolve frontend addr: %v", err)
	}

	ln, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("[ERR] listen UDP on :%s: %v", cfg.Port, err)
	}
	frontendLn = ln
	defer ln.Close()

	// Increase UDP buffer sizes for high-speed QUIC traffic
	if err := ln.SetReadBuffer(4 * 1024 * 1024); err != nil {
		log.Printf("[ERR] Failed to set UDP read buffer: %v", err)
	}
	if err := ln.SetWriteBuffer(4 * 1024 * 1024); err != nil {
		log.Printf("[ERR] Failed to set UDP write buffer: %v", err)
	}

	buf := make([]byte, 65535)
	for {
		n, clientAddr, err := ln.ReadFromUDP(buf)
		if err != nil {
			log.Printf("[ERR] read from UDP: %v", err)
			continue
		}

		packet := make([]byte, n)
		copy(packet, buf[:n])
		go handlePacket(packet, clientAddr, ac)
	}
}

func sessionKey(addr *net.UDPAddr) string {
	return addr.String()
}

func handlePacket(packet []byte, clientAddr *net.UDPAddr, ac *activator.Activator) {
	sessionsMu.RLock()
	sess := sessions[sessionKey(clientAddr)]
	sessionsMu.RUnlock()

	if sess != nil {
		// Update activity deadline on incoming traffic from client
		sess.backend.SetReadDeadline(time.Now().Add(120 * time.Second))
		sess.backend.Write(packet)
		return
	}

	if ac.IsIpActivated(clientAddr.IP.String()) {
		log.Printf("[INFO] Valid Hysteria client, forwarding → %s", clientAddr.IP.String())
		forwardToHysteria(packet, clientAddr)
		return
	}

	log.Printf("[INFO] Unknown client, forwarding to dest → %s", clientAddr.IP.String())
	forwardToDest(packet, clientAddr)
}

func forwardToHysteria(packet []byte, clientAddr *net.UDPAddr) *session {
	backendAddr, err := net.ResolveUDPAddr("udp", ":"+quicPort)
	if err != nil {
		log.Printf("[ERR] resolve hysteria addr: %v", err)
		return nil
	}

	backend, err := net.DialUDP("udp", nil, backendAddr)
	if err != nil {
		log.Printf("[ERR] dial hysteria: %v", err)
		return nil
	}

	// Increase UDP buffer sizes for backend connection
	backend.SetReadBuffer(2 * 1024 * 1024)
	backend.SetWriteBuffer(2 * 1024 * 1024)

	if _, err := backend.Write(packet); err != nil {
		log.Printf("[ERR] write to hysteria: %v", err)
		backend.Close()
		return nil
	}

	sess := &session{
		clientAddr: clientAddr,
		backend:    backend,
	}
	sessionsMu.Lock()
	sessions[sessionKey(clientAddr)] = sess
	sessionsMu.Unlock()

	go proxyUDP(sess, "hysteria")
	return sess
}

func forwardToDest(packet []byte, clientAddr *net.UDPAddr) *session {
	backendAddr, err := net.ResolveUDPAddr("udp", cfg.Dest)
	if err != nil {
		log.Printf("[ERR] resolve dest addr: %v", err)
		return nil
	}

	backend, err := net.DialUDP("udp", nil, backendAddr)
	if err != nil {
		log.Printf("[ERR] dial dest: %v", err)
		return nil
	}

	if _, err := backend.Write(packet); err != nil {
		log.Printf("[ERR] write to dest: %v", err)
		backend.Close()
		return nil
	}

	sess := &session{
		clientAddr: clientAddr,
		backend:    backend,
	}
	sessionsMu.Lock()
	sessions[sessionKey(clientAddr)] = sess
	sessionsMu.Unlock()

	go proxyUDP(sess, "dest")
	return sess
}

func proxyUDP(sess *session, target string) {
	defer func() {
		sessionsMu.Lock()
		if sessions[sessionKey(sess.clientAddr)] == sess {
			delete(sessions, sessionKey(sess.clientAddr))
		}
		sessionsMu.Unlock()
		sess.backend.Close()
	}()

	buf := make([]byte, 65535)
	for {
		sess.backend.SetReadDeadline(time.Now().Add(120 * time.Second))
		n, _, err := sess.backend.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				log.Printf("[INFO] %s proxy timeout", target)
			} else {
				log.Printf("[ERR] %s proxy read: %v", target, err)
			}
			return
		}

		if _, err := frontendLn.WriteToUDP(buf[:n], sess.clientAddr); err != nil {
			log.Printf("[ERR] write to client: %v", err)
			return
		}
	}
}
