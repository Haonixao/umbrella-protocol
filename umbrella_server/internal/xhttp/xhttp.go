package xhttp

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type httpServerConn struct {
	mu      sync.Mutex
	w       http.ResponseWriter
	flusher http.Flusher
	reader  io.ReadCloser
	closed  bool
	done    chan struct{}
	once    sync.Once
}

func newHTTPServerConn(w http.ResponseWriter, r io.ReadCloser) *httpServerConn {
	flusher, _ := w.(http.Flusher)
	return &httpServerConn{
		w:       w,
		flusher: flusher,
		reader:  r,
		done:    make(chan struct{}),
	}
}

func (c *httpServerConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func (c *httpServerConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, io.ErrClosedPipe
	}
	n, err := c.w.Write(b)
	if err == nil && c.flusher != nil {
		c.flusher.Flush()
	}
	return n, err
}

func (c *httpServerConn) Close() error {
	c.once.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
		close(c.done)
	})
	return c.reader.Close()
}

func (c *httpServerConn) Wait() <-chan struct{} {
	return c.done
}

type httpSession struct {
	uploadQueue *UploadQueue
	connected   chan struct{}
	once        sync.Once
}

func newHTTPSession(maxPackets int) *httpSession {
	return &httpSession{
		uploadQueue: NewUploadQueue(maxPackets),
		connected:   make(chan struct{}),
	}
}

func (s *httpSession) markConnected() {
	s.once.Do(func() {
		close(s.connected)
	})
}

// server struct для хранения http.Transport
type server struct {
	tr               *http.Transport
	sni              string
	filter           *allowedIPFilter
	authKey          []byte
	mu               sync.Mutex
	sessions         map[string]*httpSession
	secretPath       string
	maxBufferedPosts int
	xPaddingRange    Range
}

func (s *server) upsertSession(sessionID string) *httpSession {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[sessionID]
	if ok {
		return sess
	}

	// Создаем новую сессию (лимит 1024 пакета в очереди)
	sess = newHTTPSession(1024)
	s.sessions[sessionID] = sess

	// Автоматическое удаление "зависших" сессий через 30 секунд
	go func() {
		timer := time.NewTimer(30 * time.Second)
		defer timer.Stop()
		select {
		case <-timer.C:
			s.deleteSession(sessionID)
		case <-sess.connected:
		}
	}()

	return sess
}

func (s *server) deleteSession(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.sessions[sessionID]; ok {
		_ = sess.uploadQueue.Close()
		delete(s.sessions, sessionID)
	}
}

// Генерация случайного значения для X-Padding
func (s *server) generateRandomPadding() string {
	n := s.xPaddingRange.Rand()
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *server) handleXhttpConn(conn net.Conn) {
	defer conn.Close()

	// 1. Читаем заголовок преамбулы (теперь 2 байта)
	// [1 byte: cmd (0x01=TCP, 0x03=UDP)] [1 byte: atyp]
	cmdBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, cmdBuf); err != nil {
		return
	}
	cmd := cmdBuf[0]
	atyp := cmdBuf[1]

	var host string
	switch atyp {
	case 0x01: // IPv4
		ip := make([]byte, 4)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	case 0x03: // Domain name
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		nameLen := int(lenBuf[0])
		nameBuf := make([]byte, nameLen)
		if _, err := io.ReadFull(conn, nameBuf); err != nil {
			return
		}
		host = string(nameBuf)
	case 0x04: // IPv6
		ip := make([]byte, 16)
		if _, err := io.ReadFull(conn, ip); err != nil {
			return
		}
		host = net.IP(ip).String()
	default:
		log.Printf("[ERR] xhttp: unsupported atyp 0x%02x", atyp)
		// Шлем ошибку "Unsupported address type"
		conn.Write([]byte{0x01})
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf)
	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	// 2. Определяем тип сети и подключаемся
	network := "tcp"
	if cmd == 0x03 {
		network = "udp"
	}

	dialer := net.Dialer{Timeout: 15 * time.Second}
	remote, err := dialer.Dial(network, target)
	if err != nil {
		log.Printf("[ERR] xhttp: dial %s (%s) failed: %v", target, network, err)
		// Шлем байт ошибки (0x01), чтобы клиент получил внятный ответ, а не EOF
		conn.Write([]byte{0x01})
		return
	}
	defer remote.Close()

	// 3. Отправляем клиенту подтверждение "OK" (0x00)
	if _, err := conn.Write([]byte{0x00}); err != nil {
		log.Printf("[ERR] xhttp: failed send confirmation %s (%s) failed: %v", conn.RemoteAddr(), target, err)
		return
	}

	log.Printf("[INFO] xhttp: proxying %s → %s [%s]", conn.RemoteAddr(), target, strings.ToUpper(network))

	// 4. Запускаем bidirectional stream (используем улучшенный dualStream с WaitGroup)
	err = dualStream(remote, conn, conn)
	if err != nil && !errors.Is(err, io.EOF) {
		log.Printf("[DEBUG] xhttp: stream ended for %s: %v", target, err)
	}
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// --- 1: Проверка секретного пути ---
	// Если путь не совпадает, ведем себя как обычный сервер (404 для неизвестного пути)
	if !strings.HasPrefix(r.URL.Path, s.secretPath) {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	// --- 2: Проверка Umbrella-Client (наличие) ---
	// Если IP и путь верны, но нет секретного заголовка — это похоже на попытку
	// несанкционированного доступа к API. Отвечаем 403 Forbidden.
	if r.Header.Get("Umbrella-Client") == "" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Добавляем X-Padding в ответ (Шум метаданных)
	w.Header().Set("X-Padding", s.generateRandomPadding())
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/event-stream")

	// Извлекаем метаданные сессии
	sessionID := r.Header.Get("X-Session-ID")
	seqStr := r.Header.Get("X-Seq")

	// xhttpIsPadding := r.Header.Get("X-Is-Padding")
	// Специальный заголовок который клиент может отправить чтобы включить padding
	// Пока что выключено

	// Обработка OPTIONS (для CORS, если нужно через браузер)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	// --- РЕЖИМ: packet-up / stream-up (Uplink/Закачка) ---
	if r.Method == http.MethodPost && sessionID != "" {
		sess := s.upsertSession(sessionID)

		if seqStr != "" {
			// packet-up: один из множества пакетов
			seq, _ := strconv.ParseUint(seqStr, 10, 64)
			payload, _ := io.ReadAll(r.Body)
			err := sess.uploadQueue.Push(Packet{
				Seq:     seq,
				Payload: payload,
			})
			if err != nil {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
			w.WriteHeader(http.StatusOK)
			return
		} else {
			// stream-up upload: один длинный POST поток
			httpSC := newHTTPServerConn(w, r.Body)
			err := sess.uploadQueue.Push(Packet{
				Reader: httpSC,
			})
			if err != nil {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
			w.WriteHeader(http.StatusOK)

			// Форсируем отправку заголовков
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}

			// Keep-Alive
			// Пишем шум в тело ОТВЕТА на POST-запрос.
			// Клиент в режиме stream-up делает io.Discard для тела POST-ответа,
			// поэтому эти 'X' просто сгорят, но соединение останется живым.
			go func() {
				ticker := time.NewTicker(15 * time.Second)
				defer ticker.Stop()
				for {
					select {
					case <-ticker.C:
						// Пишем немного мусора (от 16 до 64 байт)
						noiseLen := 16 + rand.Intn(48)
						noise := make([]byte, noiseLen)
						for i := range noise {
							noise[i] = 'X'
						}
						_, err := httpSC.Write(noise)
						if err != nil {
							return // Соединение закрылось
						}
					case <-httpSC.Wait():
						return // Основной поток завершен
					}
				}
			}()

			<-httpSC.Wait() // Ждем закрытия потока
			return
		}
	}

	// --- РЕЖИМ: packet-up / stream-up (Downlink/Скачивание) ---
	if r.Method == http.MethodGet && sessionID != "" {
		sess := s.upsertSession(sessionID)
		sess.markConnected()

		w.WriteHeader(http.StatusOK)
		rc := http.NewResponseController(w)
		_ = rc.Flush()

		httpSC := newHTTPServerConn(w, r.Body)

		var remoteAddr net.Addr
		if r.ProtoAtLeast(3, 0) {
			// Если это HTTP/3, парсим как UDP
			remoteAddr, _ = net.ResolveUDPAddr("udp", r.RemoteAddr)
		} else {
			// Если это HTTP/2 или 1.1, парсим как TCP
			remoteAddr, _ = net.ResolveTCPAddr("tcp", r.RemoteAddr)
		}

		// Создаем виртуальный net.Conn
		xhttpConn := &Conn{
			writer:         NewStreamWriter(httpSC, false),
			reader:         NewStreamReader(sess.uploadQueue),
			RemoteAddrFunc: func() net.Addr { return remoteAddr },
			onClose: func() {
				s.deleteSession(sessionID)
			},
		}

		s.handleXhttpConn(xhttpConn)
		return
	}

	// --- РЕЖИМ: stream-one (Один длинный POST) ---
	if r.Method == http.MethodPost && sessionID == "" {
		w.WriteHeader(http.StatusOK)
		rc := http.NewResponseController(w)
		_ = rc.Flush()

		var remoteAddr net.Addr
		if r.ProtoAtLeast(3, 0) {
			// Если это HTTP/3, парсим как UDP
			remoteAddr, _ = net.ResolveUDPAddr("udp", r.RemoteAddr)
		} else {
			// Если это HTTP/2 или 1.1, парсим как TCP
			remoteAddr, _ = net.ResolveTCPAddr("tcp", r.RemoteAddr)
		}

		httpSC := newHTTPServerConn(w, r.Body)
		xhttpConn := &Conn{
			writer:         NewStreamWriter(httpSC, false),
			reader:         NewStreamReader(httpSC),
			RemoteAddrFunc: func() net.Addr { return remoteAddr },
		}

		s.handleXhttpConn(xhttpConn)
		return
	}

	http.NotFound(w, r)
}

type StreamWriter struct {
	w       io.WriteCloser
	disable bool // Флаг отключения паддинга для оптимизации
}

func NewStreamWriter(w io.WriteCloser, disable bool) *StreamWriter {
	return &StreamWriter{w: w, disable: disable}
}

func (s *StreamWriter) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}

	// Максимальный размер данных в одном фрейме (чтобы не превысить uint16)
	// Но на практике лучше слать кусками по 2-4 КБ
	const maxChunk = 64000
	totalWritten := 0

	for len(p) > 0 {
		chunkSize := len(p)
		if chunkSize > maxChunk {
			chunkSize = maxChunk
		}
		chunk := p[:chunkSize]

		paddingSize := 0
		if !s.disable {
			// Генерируем паддинг (от 32 до 512 байт)
			paddingSize = getRandomInt(32, 512)
		}

		// Заголовок фрейма: 4 байта
		header := make([]byte, 4)
		binary.BigEndian.PutUint16(header[0:2], uint16(chunkSize))
		binary.BigEndian.PutUint16(header[2:4], uint16(paddingSize))

		// Пишем заголовок
		if _, err := s.w.Write(header); err != nil {
			return totalWritten, err
		}

		// Пишем сами данные
		if _, err := s.w.Write(chunk); err != nil {
			return totalWritten, err
		}

		// Пишем шум (паддинг)
		if paddingSize > 0 {
			pad := make([]byte, paddingSize)
			_, _ = rand.Read(pad)
			if _, err := s.w.Write(pad); err != nil {
				return totalWritten, err
			}
		}

		p = p[chunkSize:]
		totalWritten += chunkSize
	}

	return totalWritten, nil
}

func (s *StreamWriter) Close() error {
	return s.w.Close()
}

type StreamReader struct {
	r      io.ReadCloser
	buf    *[]byte // Храним указатель на буфер из пула
	offset int     // Текущая позиция в buf
}

func NewStreamReader(r io.ReadCloser) *StreamReader {
	return &StreamReader{r: r}
}

func (s *StreamReader) releaseBuffer() {
	if s.buf != nil {
		*s.buf = (*s.buf)[:cap(*s.buf)] // Чиним длину
		UDPBufPool.Put(s.buf)
		s.buf = nil
		s.offset = 0
	}
}

func (s *StreamReader) Read(p []byte) (n int, err error) {
	// 1. Отдаем остатки из внутреннего буфера
	if s.buf != nil {
		data := (*s.buf)[s.offset:]
		n = copy(p, data)
		s.offset += n
		if s.offset >= len(*s.buf) {
			s.releaseBuffer()
		}
		return n, nil
	}

	// 2. Читаем заголовок нового фрейма
	header := make([]byte, 4)
	if _, err = io.ReadFull(s.r, header); err != nil {
		return 0, err
	}
	dataLen := int(binary.BigEndian.Uint16(header[0:2]))
	paddingSize := int(binary.BigEndian.Uint16(header[2:4]))

	// Защита от слишком больших фреймов
	if dataLen > 66*1024 {
		return 0, fmt.Errorf("frame too large: %d", dataLen)
	}

	// 3. Читаем данные
	if dataLen <= len(p) {
		n, err = io.ReadFull(s.r, p[:dataLen])
	} else {
		// Если данные не влезают в p, берем буфер из пула
		s.buf = UDPBufPool.Get().(*[]byte)
		// Обрезаем срез до нужной длины данных
		*s.buf = (*s.buf)[:dataLen]
		_, err = io.ReadFull(s.r, *s.buf)
		if err != nil {
			s.releaseBuffer() // Возвращаем при ошибке чтения
			return 0, err
		}
		n = copy(p, *s.buf)
		s.offset = n
	}

	// 4. Сбрасываем паддинг
	if paddingSize > 0 {
		io.CopyN(io.Discard, s.r, int64(paddingSize))
	}

	return n, err
}

func (s *StreamReader) Close() error {
	s.releaseBuffer() // Гарантируем возврат буфера в пул при закрытии
	return s.r.Close()
}
