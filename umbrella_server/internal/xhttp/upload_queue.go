package xhttp

import (
	"errors"
	"io"
	"sync"
	"time"
)

var ErrQueueTooLarge = errors.New("packet queue is too large")

type Packet struct {
	Seq     uint64
	Payload []byte // UploadQueue will hold Payload, so never reuse it after UploadQueue.Push
	Reader  io.ReadCloser
}

type UploadQueue struct {
	mu         sync.Mutex
	pushNotify chan struct{} // Канал для уведомления о поступлении данных
	condPushed sync.Cond
	condPopped sync.Cond
	packets    map[uint64][]byte
	nextSeq    uint64
	buf        []byte
	closed     bool
	maxPackets int
	reader     io.ReadCloser
}

func NewUploadQueue(maxPackets int) *UploadQueue {
	q := &UploadQueue{
		packets:    make(map[uint64][]byte, maxPackets),
		maxPackets: maxPackets,
		pushNotify: make(chan struct{}, 1), // Буферизованный, чтобы не блокировать Push
	}
	q.condPopped = sync.Cond{L: &q.mu}
	return q
}

func (q *UploadQueue) Push(p Packet) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.closed {
		return io.ErrClosedPipe
	}

	if p.Reader != nil {
		q.reader = p.Reader
		q.notifyPushed()
		return nil
	}

	for len(q.packets) > q.maxPackets {
		q.condPopped.Wait()
		if q.closed {
			return io.ErrClosedPipe
		}
	}

	q.packets[p.Seq] = p.Payload
	q.notifyPushed()
	return nil
}

// Вспомогательный метод для уведомления
func (q *UploadQueue) notifyPushed() {
	select {
	case q.pushNotify <- struct{}{}:
	default:
	}
}

func (q *UploadQueue) Read(b []byte) (int, error) {
	q.mu.Lock()

	for {
		// 1. Если есть остатки в буфере - отдаем
		if len(q.buf) > 0 {
			n := copy(b, q.buf)
			q.buf = q.buf[n:]
			q.mu.Unlock()
			return n, nil
		}

		// 2. Ищем строго следующий пакет по Seq
		if payload, ok := q.packets[q.nextSeq]; ok {
			delete(q.packets, q.nextSeq)
			q.nextSeq++
			q.buf = payload
			q.condPopped.Broadcast()
			continue
		}

		// 3. Если это stream-up (не packet-up), читаем напрямую
		if reader := q.reader; reader != nil {
			q.mu.Unlock()
			return reader.Read(b)
		}

		if q.closed {
			q.mu.Unlock()
			return 0, io.EOF
		}

		// 5. ОЖИДАНИЕ С ТАЙМАУТОМ (Ключевое изменение)
		q.mu.Unlock() // Разблокируем на время ожидания

		select {
		case <-q.pushNotify:
			// Кто-то сделал Push, пробуем прочитать в следующей итерации цикла
			q.mu.Lock()
		case <-time.After(50 * time.Millisecond):
			q.mu.Lock()
		}
	}
}

func (q *UploadQueue) Close() error {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.closed = true
	if q.reader != nil {
		_ = q.reader.Close()
	}
	q.notifyPushed() // Разблокируем Read
	q.condPopped.Broadcast()
	return nil
}
