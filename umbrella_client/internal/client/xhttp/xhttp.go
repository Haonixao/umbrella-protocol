package xhttp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptrace"
	"strconv"
	"sync"
	"time"

	"umbrella_client/internal/client/share"

	"github.com/apernet/quic-go/http3"
)

// WaitReadCloser is an io.ReadCloser that blocks on Read() until the underlying
// ReadCloser is provided via Set(). This enables returning a reader immediately
// while the actual HTTP response body is obtained asynchronously in a goroutine,
// breaking the synchronous RoundTrip deadlock with CDN header buffering.
type WaitReadCloser struct {
	wait chan struct{}
	once sync.Once
	rc   io.ReadCloser
	err  error
}

func NewWaitReadCloser() *WaitReadCloser {
	return &WaitReadCloser{wait: make(chan struct{})}
}

// Set provides the underlying ReadCloser and unblocks any pending Read calls.
// Must be called at most once. If Close was already called, rc is closed to
// prevent leaks.
func (w *WaitReadCloser) Set(rc io.ReadCloser) {
	w.setup(rc, nil)
}

// CloseWithError records an error and unblocks any pending Read calls.
func (w *WaitReadCloser) CloseWithError(err error) {
	w.setup(nil, err)
}

// setup sets the underlying ReadCloser and error.
func (w *WaitReadCloser) setup(rc io.ReadCloser, err error) {
	w.once.Do(func() {
		w.rc = rc
		w.err = err
		close(w.wait)
	})
	if w.err != nil && rc != nil {
		_ = rc.Close()
	}
}

func (w *WaitReadCloser) Read(b []byte) (int, error) {
	<-w.wait
	if w.rc == nil {
		return 0, w.err
	}
	return w.rc.Read(b)
}

func (w *WaitReadCloser) Close() error {
	w.setup(nil, net.ErrClosed)
	<-w.wait
	if w.rc != nil {
		return w.rc.Close()
	}
	return nil
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

type Client struct {
	ctx       context.Context
	cancel    context.CancelFunc
	host      string
	path      string
	authKey   string
	mode      string // stream-one, stream-up, packet-up
	transport http.RoundTripper
}

func (c *Client) Close() error {
	defer func() {
		// Ensure we always call finish and handle panics
		if r := recover(); r != nil {
			log.Printf("[ERR] panic on client closing")
		}
	}()
	if c.ctx != nil && c.ctx.Err() == nil {
		// Отменяет контекст, останавливая все горутины Dial и Writer
		c.cancel()
	}

	if t, ok := c.transport.(*http.Transport); ok {
		t.CloseIdleConnections()
	}

	if t, ok := c.transport.(*http3.Transport); ok {
		_ = t.Close()
	}

	return nil
}

func (c *Client) Dial(ctx context.Context, isUDP bool) (net.Conn, error) {
	var (
		res net.Conn
		err error
	)
	switch c.mode {
	case "stream-one":
		res, err = c.DialStreamOne(ctx)
	case "stream-up":
		res, err = c.DialStreamUp(ctx)
	case "packet-up":
		res, err = c.DialPacketUp(ctx, isUDP)
	default:
		res, err = nil, fmt.Errorf("unknown mode: %s", c.mode)
	}
	if err != nil {
		// Если соединение не удалось, сбрасываем флаг активации.
		// Возможно, сервер перезагрузился или наш IP вылетел из белого списка.
		log.Printf("[ERR] Dial: %v", err)
		isActivated.Store(false)
		return nil, err
	}
	return res, nil
}

// DialStreamOne: Один длинный POST запрос для Up и Down
func (c *Client) DialStreamOne(ctx context.Context) (net.Conn, error) {
	pr, pw := io.Pipe()
	// Оборачиваем pw, чтобы он добавлял [2:DataLen][2:PaddingLen]
	writer := NewStreamWriter(pw, false)

	wrc := NewWaitReadCloser()
	conn := &Conn{writer: writer, reader: wrc}

	gotConn := make(chan bool, 1)
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) { gotConn <- true },
	}

	req, _ := http.NewRequestWithContext(httptrace.WithClientTrace(c.ctx, trace), "POST", c.url(), pr)
	c.fillHeaders(req, "")

	go func() {
		resp, err := c.transport.RoundTrip(req)
		if err != nil {
			wrc.CloseWithError(err)
			return
		}
		if resp.StatusCode != http.StatusOK {
			wrc.CloseWithError(fmt.Errorf("bad status: %d", resp.StatusCode))
			return
		}
		reader := NewStreamReader(resp.Body)
		wrc.Set(reader)
	}()

	if !waitGotConn(gotConn, ctx) {
		return nil, fmt.Errorf("dial timeout or failed")
	}

	return conn, nil
}

// DialStreamUp: GET для чтения, POST для записи
func (c *Client) DialStreamUp(ctx context.Context) (net.Conn, error) {
	sessionID := c.genSessionID()
	pr, pw := io.Pipe()
	writer := NewStreamWriter(pw, false)

	wrc := NewWaitReadCloser()
	conn := &Conn{writer: writer, reader: wrc}

	gotConn := make(chan bool, 1)
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) { gotConn <- true },
	}

	// 1. Запускаем Download (GET)
	go func() {
		req, _ := http.NewRequestWithContext(httptrace.WithClientTrace(c.ctx, trace), "GET", c.url(), nil)
		c.fillHeaders(req, sessionID)
		resp, err := c.transport.RoundTrip(req)
		if err != nil {
			wrc.CloseWithError(err)
			return
		}
		reader := NewStreamReader(resp.Body)
		wrc.Set(reader)
	}()

	if !waitGotConn(gotConn, ctx) {
		return nil, fmt.Errorf("dial timeout")
	}

	// 2. Запускаем Uplink (POST)
	go func() {
		req, _ := http.NewRequestWithContext(c.ctx, "POST", c.url(), pr)
		c.fillHeaders(req, sessionID)
		resp, err := c.transport.RoundTrip(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body)
	}()

	return conn, nil
}

// DialPacketUp: GET для чтения, много POST для записи
func (c *Client) DialPacketUp(ctx context.Context, isUDP bool) (net.Conn, error) {
	sessionID := c.genSessionID()
	writer := NewPacketUpWriter(c.ctx, c.host, c.path, sessionID, c.transport, isUDP)

	wrc := NewWaitReadCloser()
	conn := &Conn{writer: writer, reader: wrc}

	gotConn := make(chan bool, 1)
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) { gotConn <- true },
	}

	go func() {
		req, _ := http.NewRequestWithContext(httptrace.WithClientTrace(c.ctx, trace), "GET", c.url(), nil)
		c.fillHeaders(req, sessionID)
		resp, err := c.transport.RoundTrip(req)
		if err != nil {
			wrc.CloseWithError(err)
			return
		}
		reader := NewStreamReader(resp.Body)
		wrc.Set(reader)
	}()

	if !waitGotConn(gotConn, ctx) {
		return nil, fmt.Errorf("dial timeout")
	}

	return conn, nil
}

// Вспомогательные методы
func (c *Client) url() string { return "https://" + c.host + c.path }

// genSessionID создает просто уникальный технический ID для связки GET/POST.
func (c *Client) genSessionID() string {
	return generateRandomString(16, 16)
}

func (c *Client) fillHeaders(req *http.Request, sid string) {
	req.Host = c.host
	req.Header.Set("Umbrella-Client", generateRandomString(4, 32))
	if sid != "" {
		req.Header.Set("X-Session-ID", sid)
	}
	// Добавляем X-Padding для маскировки длины заголовков
	req.Header.Set("X-Padding", generateRandomString(32, 512))
	// req.Header.Set(X-Is-Padding", "...")
	// Специальный заголовок который клиент может отправить чтобы включить padding
	// Пока что выключено
}

func waitGotConn(ch chan bool, ctx context.Context) bool {
	select {
	case ok := <-ch:
		return ok
	case <-ctx.Done():
		return false
	case <-time.After(15 * time.Second):
		return false
	}
}

type PacketUpWriter struct {
	ctx       context.Context
	cancel    context.CancelFunc
	host      string
	path      string
	sessionID string
	transport http.RoundTripper

	maxEachPostBytes      int
	minPostsIntervalRange [2]int // [min, max] в мс
	disablePayloadPadding bool

	writeMu   sync.Mutex
	writeCond sync.Cond
	seq       uint64
	buf       []byte
	timer     *time.Timer
	flushErr  error

	sem   chan struct{}
	IsUDP bool
}

// NewPacketUpWriter создает адаптированный писатель для режима packet-up
func NewPacketUpWriter(ctx context.Context, host, path, sessionID string, transport http.RoundTripper, isUDP bool) *PacketUpWriter {
	wCtx, cancel := context.WithCancel(ctx)
	w := &PacketUpWriter{
		ctx:                   wCtx,
		cancel:                cancel,
		host:                  host,
		path:                  path,
		sessionID:             sessionID,
		transport:             transport,
		maxEachPostBytes:      64000,
		minPostsIntervalRange: [2]int{10, 100}, // Пауза между POST-запросами
		buf:                   make([]byte, 0, 64000),
		sem:                   make(chan struct{}, 2),
		IsUDP:                 isUDP,
	}
	w.writeCond.L = &w.writeMu
	return w
}

func (c *PacketUpWriter) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if err := c.flushErr; err != nil {
		return 0, err
	}

	if len(b) == 0 {
		return 0, nil
	}

	// РЕЖИМ UDP: Отправляем каждый Write как отдельный пакет немедленно
	if c.IsUDP {
		// Если в буфере что-то было (маловероятно для UDP, но для безопасности), сбрасываем
		if len(c.buf) > 0 {
			c.internalFlushLocked()
		}

		// Копируем и отправляем текущий пакет
		dataToSend := make([]byte, len(b))
		copy(dataToSend, b)

		currentSeq := c.seq
		c.seq++

		go func(data []byte, s uint64) {
			c.sem <- struct{}{}
			defer func() { <-c.sem }()
			if _, err := c.sendPacket(data, s); err != nil {
				c.writeMu.Lock()
				c.flushErr = err
				c.writeMu.Unlock()
			}
		}(dataToSend, currentSeq)

		return len(b), nil
	}

	// РЕЖИМ TCP: Стандартная логика с буферизацией и нарезкой
	dataLen := len(b)
	cursor := 0
	for cursor < dataLen {
		if c.timer == nil {
			interval := c.getRandomInterval()
			c.timer = time.AfterFunc(time.Duration(interval)*time.Millisecond, c.flush)
		}

		remain := c.maxEachPostBytes - len(c.buf)
		if remain > 0 {
			toWrite := dataLen - cursor
			if toWrite > remain {
				toWrite = remain
			}
			c.buf = append(c.buf, b[cursor:cursor+toWrite]...)
			cursor += toWrite
		}

		if len(c.buf) >= c.maxEachPostBytes {
			c.internalFlushLocked()
		}
	}
	return dataLen, nil
}

func (c *PacketUpWriter) flush() {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.internalFlushLocked()
}

func (c *PacketUpWriter) internalFlushLocked() {
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	if len(c.buf) == 0 || c.flushErr != nil {
		return
	}

	// Копируем данные для отправки и очищаем буфер
	dataToSend := make([]byte, len(c.buf))
	copy(dataToSend, c.buf)
	c.buf = c.buf[:0]

	currentSeq := c.seq
	c.seq++

	// Запускаем отправку в горутине, чтобы не блокировать Write
	// UploadQueue на сервере сама разберется с порядком через Seq
	c.sem <- struct{}{} // Занимаем слот
	go func(data []byte, s uint64) {
		defer func() { <-c.sem }() // Освобождаем слот

		if _, err := c.sendPacket(data, s); err != nil {
			c.writeMu.Lock()
			c.flushErr = err
			c.writeMu.Unlock()
		}
	}(dataToSend, currentSeq)
}

func (c *PacketUpWriter) sendPacket(b []byte, seq uint64) (int, error) {
	paddingSize := 0
	if !c.disablePayloadPadding {
		paddingSize = c.getRandomPadding(32, 512)
	}

	frame := make([]byte, 4+len(b)+paddingSize)
	binary.BigEndian.PutUint16(frame[0:2], uint16(len(b)))
	binary.BigEndian.PutUint16(frame[2:4], uint16(paddingSize))
	copy(frame[4:], b)
	if paddingSize > 0 {
		_, _ = rand.Read(frame[4+len(b):])
	}

	u := fmt.Sprintf("https://%s%s", c.host, c.path)
	req, err := http.NewRequestWithContext(c.ctx, http.MethodPost, u, bytes.NewReader(frame))
	if err != nil {
		return 0, err
	}

	req.Host = c.host
	req.Header.Set("Umbrella-Client", generateRandomString(4, 32))
	req.Header.Set("X-Session-ID", c.sessionID)
	req.Header.Set("X-Seq", strconv.FormatUint(seq, 10))
	req.Header.Set("X-Padding", c.generateHeaderPadding())

	// req.Header.Set(X-Is-Padding", "...")
	// Специальный заголовок который клиент может отправить чтобы включить padding
	// Пока что выключено

	resp, err := c.transport.RoundTrip(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("xhttp packet-up bad status: %d", resp.StatusCode)
	}
	return len(b), nil
}

// Вспомогательные методы
func (c *PacketUpWriter) getRandomInterval() int {
	diff := c.minPostsIntervalRange[1] - c.minPostsIntervalRange[0]
	if diff <= 0 {
		return c.minPostsIntervalRange[0]
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(diff)))
	return c.minPostsIntervalRange[0] + int(n.Int64())
}

func (c *PacketUpWriter) getRandomPadding(min, max int) int {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max-min)))
	return min + int(n.Int64())
}

func (c *PacketUpWriter) generateHeaderPadding() string {
	size := c.getRandomPadding(32, 512)
	b := make([]byte, size/2)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (c *PacketUpWriter) Close() error {
	c.flush()
	c.cancel()
	return nil
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
		share.UDPBufPool.Put(s.buf)
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
		s.buf = share.UDPBufPool.Get().(*[]byte)
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
