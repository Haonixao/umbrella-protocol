package xhttp

import (
	"io"
	"net"
	"net/http"
	"sync"
)

var bufferPool = sync.Pool{
	New: func() any { b := make([]byte, 66*1024); return &b },
}

func closeWrite(c io.Closer) {
	if c == nil {
		return
	}
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
		return
	}
	c.Close()
}

type closeWriter interface {
	CloseWrite() error
}

// dualStream copies bytes from target to clientWriter and from clientReader to target.
func dualStream(target net.Conn, clientReader io.ReadCloser, clientWriter io.Writer) error {
	var wg sync.WaitGroup
	wg.Add(2)

	// Функция для закрытия всего в самом конце
	closeAll := func() {
		target.Close()
		clientReader.Close()
		if cw, ok := clientWriter.(io.Closer); ok {
			cw.Close()
		}
	}
	// Гарантируем полную очистку ресурсов ПОСЛЕ того, как обе горутины закончат работу
	defer closeAll()

	stream := func(w io.Writer, r io.Reader) {
		defer wg.Done()

		bufPtr := bufferPool.Get().(*[]byte)
		buf := *bufPtr
		buf = buf[0:cap(buf)]
		defer bufferPool.Put(bufPtr)

		// Копируем данные
		_, _ = flushingIoCopy(w, r, buf)

		// Посылаем сигнал о завершении записи в одну сторону (Half-Close)
		// Это позволяет серверу/клиенту понять, что данных больше не будет,
		// но при этом продолжать слать данные в обратном направлении.
		if cw, ok := w.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
	}

	go stream(target, clientReader) // Uplink
	stream(clientWriter, target)    // Downlink

	wg.Wait() // Ждем завершения обоих направлений
	return nil
}

// flushingIoCopy is analogous to buffering io.Copy(), but also attempts to flush on each iteration.
// If dst does not implement http.ResponseWriter, it will do a simple io.CopyBuffer().
// Based on forwardproxy implementation.
func flushingIoCopy(dst io.Writer, src io.Reader, buf []byte) (written int64, err error) {
	rw, ok := dst.(http.ResponseWriter)
	var rc *http.ResponseController
	if ok {
		rc = http.NewResponseController(rw)
	}

	for {
		var nr int
		var er error

		nr, er = src.Read(buf)

		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if rc != nil {
				_ = rc.Flush()
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return
}
