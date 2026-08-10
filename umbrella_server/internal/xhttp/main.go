package xhttp

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"log"
	"math/rand"
	"net"
	"net/http"
	"time"

	"umbrella_server/internal/config"

	"github.com/apernet/hysteria/core/v2/congestion"
	"github.com/apernet/hysteria/core/v2/congestion/bbr"
	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"golang.org/x/net/http2"
)

func XhttpStarter(cfg *config.Config) {
	rand.New(rand.NewSource(time.Now().UnixNano()))
	log.Printf("[INFO] Umbrella/Xhttp server on :%s (fallback → %s)", cfg.Port, cfg.Dest)

	var authKey []byte

	if cfg.Xhttp.AuthKey == "" {
		authKey = make([]byte, 32)
		if _, err := rand.Read(authKey); err != nil {
			log.Fatalf("[ERR] generate auth key: %v", err)
		}
		log.Printf("[INFO] Generated auth-key — save this for client: %s", hex.EncodeToString(authKey))
	} else {
		var err error
		authKey, err = hex.DecodeString(cfg.Xhttp.AuthKey)
		if err != nil || len(authKey) != 32 {
			log.Fatalf("[ERR] auth-key must be 32 bytes (64 hex chars)")
		}
	}

	filter := &allowedIPFilter{allowed: make(map[string]bool)}

	certPEM, keyPEM, err := GenCertInMemory(cfg.Dest)
	if err != nil {
		log.Fatalf("[ERR] cert: %v", err)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		log.Fatalf("[ERR] cert: %v", err)
	}

	// Общий конфиг для TLS
	baseTlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	// Конфиг для HTTP/2 (TCP)
	h2TlsCfg := baseTlsCfg.Clone()
	h2TlsCfg.NextProtos = []string{"h2", "http/1.1"}

	l, err := net.Listen("tcp", ":"+cfg.Port)
	if err != nil {
		log.Fatal(err)
	}

	f := &ipFilterListener{
		inner:   l,
		filter:  filter,
		dest:    cfg.Dest,
		authKey: authKey,
	}

	// Инициализируем http.Transport
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		// --- БУСТ КОННЕКШН-ПУЛА ---
		MaxIdleConns:           1000,        // Увеличиваем с 100 до 1000
		MaxIdleConnsPerHost:    100,         // Важно для многопоточной загрузки с одного хоста
		MaxResponseHeaderBytes: 1024 * 1024, // 1MB на заголовки (защита от некоторых сайтов)

		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 30 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	// Создаем экземпляр нашей структуры server
	s := &server{
		tr:               tr,
		sni:              cfg.Dest,
		filter:           filter,
		authKey:          authKey,
		sessions:         map[string]*httpSession{},
		secretPath:       cfg.Xhttp.Path,
		xPaddingRange:    Range{Min: 32, Max: 512},
		maxBufferedPosts: 64,
	}

	// Создаем http.Server с базовыми таймаутами
	httpServer := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           s,
		TLSConfig:         h2TlsCfg,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       10 * time.Minute,

		ReadTimeout:  0, // Не ограничиваем время чтения тела (важно для стримов)
		WriteTimeout: 0, // Не ограничиваем время записи тела
	}

	// Явно настраиваем HTTP/2 для httpServer с оптимизированными параметрами
	h2srv := &http2.Server{
		MaxConcurrentStreams: 1000,
		MaxReadFrameSize:     1024 * 1024,
		IdleTimeout:          10 * time.Minute,
	}

	if err := http2.ConfigureServer(httpServer, h2srv); err != nil {
		log.Fatalf("[ERR] configure HTTP/2: %v", err)
	}

	q := &quicFrontend{
		filter:      filter,
		dest:        cfg.Dest,
		backend:     "127.0.0.1:8443",
		authKey:     authKey,
		sessions:    map[string]*udpSession{},
		sessionWait: make(map[string]chan struct{}),
	}
	go q.Start(":" + cfg.Port)

	h3TlsCfg := baseTlsCfg.Clone()
	h3TlsCfg.NextProtos = []string{"h3"}
	h3TlsCfg.MinVersion = tls.VersionTLS13

	var defaultStreamReceiveWindow uint64 = 8 * 1024 * 1024 // 8 МБ

	h3srv := &http3.Server{
		Addr:      "127.0.0.1:8443",
		Handler:   s,
		TLSConfig: h3TlsCfg,
		QUICConfig: &quic.Config{
			MaxIdleTimeout:     10 * time.Minute,
			MaxIncomingStreams: 1024,
			EnableDatagrams:    true,

			// Начальное окно для одного стрима (8 МБ)
			InitialStreamReceiveWindow: defaultStreamReceiveWindow,
			// Максимальное окно для одного стрима
			MaxStreamReceiveWindow: defaultStreamReceiveWindow,
			// Начальное окно для всего соединения (12 МБ)
			InitialConnectionReceiveWindow: defaultStreamReceiveWindow * 5 / 2,
			// Максимальное окно для всего соединения
			MaxConnectionReceiveWindow: defaultStreamReceiveWindow * 5 / 2,

			// Позволяет серверу предлагать клиенту оптимальный MTU
			DisablePathMTUDiscovery: false,

			DisablePathManager: true,
		},
		ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
			congestion.UseBBR(conn, bbr.Profile("aggressive"))
			return ctx
		},
	}
	go func() {
		if err := h3srv.ListenAndServe(); err != nil {
			log.Fatalf("[ERR] QUIC Backend error: %v", err)
		}
	}()

	log.Fatal(httpServer.Serve(tls.NewListener(f, h2TlsCfg)))
}
