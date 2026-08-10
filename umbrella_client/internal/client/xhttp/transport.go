package xhttp

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/apernet/hysteria/core/v2/congestion"
	"github.com/apernet/hysteria/core/v2/congestion/bbr"
	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

// Глобальный флаг активации IP на сервере
var isActivated atomic.Bool

// --- QUIC (H3) CID Generator ---

type customCIDGenerator struct {
	authKey []byte
	host    string
}

func (g *customCIDGenerator) GenerateConnectionID() (quic.ConnectionID, error) {
	// Если уже активированы — выдаем обычный случайный ID (как делает стандартный quic-go)
	if isActivated.Load() {
		b := make([]byte, 20)
		_, _ = rand.Read(b)
		return quic.ConnectionIDFromBytes(b), nil
	}

	rnd := make([]byte, 5)
	_, _ = rand.Read(rnd)

	// Минуты с начала года
	now := time.Now().UTC()
	yearStart := time.Date(now.Year(), 1, 1, 0, 0, 0, 0, time.UTC)
	minutes := uint32(now.Sub(yearStart).Minutes())

	minBytes := make([]byte, 3)
	minBytes[0], minBytes[1], minBytes[2] = byte(minutes>>16), byte(minutes>>8), byte(minutes)

	// XOR маскировка времени
	maskedTime := make([]byte, 3)
	for i := 0; i < 3; i++ {
		maskedTime[i] = minBytes[i] ^ rnd[i]
	}

	// HMAC подпись
	mac := hmac.New(sha256.New, g.authKey)
	mac.Write(rnd)
	mac.Write(minBytes)
	mac.Write([]byte(g.host))
	signature := mac.Sum(nil)[:12]

	// CID: [Rnd:5][MaskedTime:3][Signature:12] = 20 байт
	cid := make([]byte, 20)
	copy(cid[0:5], rnd)
	copy(cid[5:8], maskedTime)
	copy(cid[8:20], signature)

	return quic.ConnectionIDFromBytes(cid), nil
}

func (g *customCIDGenerator) ConnectionIDLen() int {
	return 20
}

// --- TLS (H2) Auth Helper ---

func generateTLSMagicSessionID(authKey []byte, host string) []byte {
	rnd := make([]byte, 5)
	_, _ = rand.Read(rnd)

	now := time.Now().UTC()
	yearStart := time.Date(now.Year(), 1, 1, 0, 0, 0, 0, time.UTC)
	minutes := uint32(now.Sub(yearStart).Minutes())

	minBytes := []byte{byte(minutes >> 16), byte(minutes >> 8), byte(minutes)} // 3 байта

	maskedTime := make([]byte, 3)
	for i := 0; i < 3; i++ {
		maskedTime[i] = minBytes[i] ^ rnd[i]
	}

	mac := hmac.New(sha256.New, authKey)
	mac.Write(rnd)
	mac.Write(minBytes)
	mac.Write([]byte(host))
	signature := mac.Sum(nil)[:24] // Нужно 24 байта

	sid := make([]byte, 32)
	copy(sid[0:5], rnd)
	copy(sid[5:8], maskedTime)
	copy(sid[8:32], signature)
	return sid
}

// --- Transport Factory ---

func NewTransport(serverAddr string, host string, alpn []string, authKeyHex string) http.RoundTripper {
	authKey, _ := hex.DecodeString(authKeyHex)

	// 1. Режим HTTP/3 (QUIC)
	if len(alpn) == 1 && alpn[0] == "h3" {

		// Создаем UDP сокет один раз для всего транспорта
		udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		if err != nil {
			log.Printf("[ERR] udp: %v", err)
			return nil
		}

		// Создаем quic.Transport и вставляем наш генератор
		tr := &quic.Transport{
			Conn: udpConn,
		}

		// Если мы еще не активированы, ставим наш магический генератор
		magicGen := &customCIDGenerator{authKey: authKey, host: host}
		tr.ConnectionIDGenerator = magicGen

		// Создаем базовый TLS конфиг для H3
		h3TlsCfg := &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
			NextProtos:         []string{"h3"},
		}

		var defaultStreamReceiveWindow uint64 = 8 * 1024 * 1024 // 8 МБ

		return &http3.Transport{
			TLSClientConfig: h3TlsCfg,
			QUICConfig: &quic.Config{
				MaxIdleTimeout:  30 * time.Second,
				KeepAlivePeriod: 10 * time.Second,

				// Начальное окно для одного стрима (8 МБ)
				InitialStreamReceiveWindow: defaultStreamReceiveWindow,
				// Максимальное окно для одного стрима
				MaxStreamReceiveWindow: defaultStreamReceiveWindow,
				// Начальное окно для всего соединения (12 МБ)
				InitialConnectionReceiveWindow: defaultStreamReceiveWindow * 5 / 2,
				// Максимальное окно для всего соединения
				MaxConnectionReceiveWindow: defaultStreamReceiveWindow * 5 / 2,

				// Разрешаем датаграммы для UDP Relay
				EnableDatagrams: true,

				// Оптимизация MTU для обхода ТСПУ (чуть меньше стандартного)
				// Чтобы избежать фрагментации UDP, которая часто режется
				DisablePathMTUDiscovery: false,

				DisablePathManager: true,
			},
			Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
				var conf *tls.Config
				if tlsCfg != nil {
					conf = tlsCfg.Clone()
				} else {
					conf = h3TlsCfg.Clone()
				}

				conf.InsecureSkipVerify = true
				conf.ServerName = host
				if len(conf.NextProtos) == 0 {
					conf.NextProtos = []string{"h3"}
				}

				udpAddr, err := net.ResolveUDPAddr("udp", serverAddr)
				if err != nil {
					return nil, fmt.Errorf("resolve udp addr %s: %w", serverAddr, err)
				}
				// Используем DialEarly через наш Transport
				// Он автоматически применит tr.ConnectionIDGenerator
				conn, err := tr.DialEarly(ctx, udpAddr, conf, cfg)
				if err != nil {
					log.Printf("[DEBUG] QUIC DialEarly error: %v", err)
				}

				if err == nil && !isActivated.Load() {
					isActivated.Store(true)
					log.Printf("[INFO] xhttp: H3 IP activation successful via Knock")
				}

				congestion.UseBBR(conn, bbr.Profile("aggressive"))
				// or
				// var speedMbps uint64 = 100
				// actualTx := speedMbps * 1024 * 1024 / 8
				// congestion.UseBrutal(conn, actualTx, false)

				return conn, err
			},
		}
	}

	// 2. Режим HTTP/2 (uTLS)
	tr := &http2.Transport{
		// В http2.Transport логика DialTLSContext заменяет собой всё остальное
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			dialer := &net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}
			// РЕДИРЕКТ: подключаемся к нашему серверу (serverAddr), игнорируя addr (sni)
			rawConn, err := dialer.DialContext(ctx, network, serverAddr)
			if err != nil {
				log.Printf("[ERR] dial: %v", err)
				return nil, err
			}

			// Выбираем отпечаток Chrome
			uConn := utls.UClient(rawConn, &utls.Config{
				ServerName:         host, // SNI оставляем целевым (Steam)
				InsecureSkipVerify: true,
			}, utls.HelloChrome_Auto)

			uConn.BuildHandshakeState()

			if !isActivated.Load() {
				uConn.HandshakeState.Hello.SessionId = generateTLSMagicSessionID(authKey, host)
			} else {
				b := make([]byte, 32)
				_, _ = rand.Read(b)
				uConn.HandshakeState.Hello.SessionId = b
			}

			if err := uConn.HandshakeContext(ctx); err != nil {
				_ = rawConn.Close()
				return nil, err
			}
			log.Printf("[INFO] xhttp: H2 IP activation successful via Knock")
			isActivated.Store(true)
			return uConn, nil
		},
		// Настройки мультиплексирования H2
		ReadIdleTimeout: 30 * time.Second, // Чтобы быстрее обнаруживать "повисшие" соединения
		PingTimeout:     15 * time.Second,
		// Отключаем проверку на стандартный tls.Conn
		AllowHTTP: false,
	}
	return tr
}
