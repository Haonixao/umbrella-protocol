package decoy

import (
	"context"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

var defaultDecoyHosts = []string{
	"google.com", "fonts.googleapis.com", "github.com", "github.githubassets.com",
	"cloudflare.com", "dash.cloudflare.com", "microsoft.com", "visualstudio.microsoft.com",
	"go.dev", "python.org", "docker.com", "hub.docker.com", "stackoverflow.com",
	"aviasales.ru", "vk.ru", "yandex.ru", "dzen.ru", "yandex.md", "yastatic.net",
	"ozon.com", "mail.ru", "gosuslugi.ru", "apteka.ru", "eapteka.ru", "sberbank.com",
	"sberbank.ru", "tbank.ru", "habr.com", "pikabu.ru", "avito.ru", "wildberries.ru",
}

// StartGlobalDecoy запускает фоновые HTTP запросы напрямую (не через туннель)
// для размытия статистики соединений клиента в глазах провайдера.
func StartGlobalDecoy(ctx context.Context) {
	log.Printf("[INFO] Decoy: Starting global background traffic (direct mode)")

	for {
		minutes := rand.Intn(3) + 1
		// Рандомная пауза от 1 до 3 минут
		jitter := time.Duration(minutes) * time.Minute
		// Выполняем 2-5 запроса за раз
		numReqs := rand.Intn(4) + 2

		log.Printf("[INFO] Decoy: Waiting %d minutes for next batch of %d decoys...", minutes, numReqs)

		select {
		case <-ctx.Done():
			return
		case <-time.After(jitter):
		}

		log.Printf("[INFO] Decoy: Starting batch of %d decoys", numReqs)

		for i := 0; i < numReqs; i++ {
			host := defaultDecoyHosts[rand.Intn(len(defaultDecoyHosts))]

			runDecoy(host)

			// Небольшая пауза между запросами в пачке
			time.Sleep(time.Duration(rand.Intn(500)+100) * time.Millisecond)
		}
	}
}

func runDecoy(host string) {
	addr := host
	if !strings.Contains(addr, ":") {
		addr += ":443"
	}

	log.Printf("[INFO] Initiating connection %s", host)

	// 1. Dial TCP
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		log.Printf("[ERR] TCP dial failed %s: %v", host, err)
		return
	}
	defer conn.Close()

	// 2. Wrap with uTLS (Chrome mimic)
	config := &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
	}
	uConn := utls.UClient(conn, config, utls.HelloChrome_Auto)

	// 3. Handshake
	uConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := uConn.Handshake(); err != nil {
		log.Printf("[ERR] TLS handshake failed %s: %v", host, err)
		return
	}

	negotiated := uConn.ConnectionState().NegotiatedProtocol
	log.Printf("[INFO] Handshake successful %s (ALPN: %s)", host, negotiated)

	// 4. Send minimal request based on protocol
	if negotiated == "h2" {
		// HTTP/2 Connection Preface + Empty SETTINGS frame
		// This is the bare minimum to look like a starting H2 connection
		preface := "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
		settings := []byte{0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00}
		if _, err := uConn.Write(append([]byte(preface), settings...)); err != nil {
			log.Printf("[ERR] Failed to send H2 preface %s: %v", host, err)
			return
		}
	} else {
		// 4. Send HEAD request (HTTP/1.1)
		req := fmt.Sprintf("HEAD / HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36\r\n"+
			"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8\r\n"+
			"Accept-Language: en-US,en;q=0.9\r\n"+
			"Connection: close\r\n\r\n", host)

		if _, err := uConn.Write([]byte(req)); err != nil {
			log.Printf("[ERR] Failed to send HEAD request %s: %v", host, err)
			return
		}
	}

	// 5. Read a bit of data to satisfy DPI
	uConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	respBuf := make([]byte, 1024)
	n, err := uConn.Read(respBuf)
	if err != nil && err != io.EOF {
		// In H2, the server might wait for more frames, which is fine
		log.Printf("[ERR] Read finished/failed %s: %v", host, err)
	} else if n > 0 {
		log.Printf("[INFO] %s received %d bytes of response data", host, n)
	}

	log.Printf("[INFO] %s connection closed.", host)
}
