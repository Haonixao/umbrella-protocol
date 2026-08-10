package xhttp

import (
	"errors"
	"io"
	"net"
	"time"
)

type Conn struct {
	writer  io.WriteCloser
	reader  io.ReadCloser
	onClose func()

	LocalAddrFunc  func() net.Addr
	RemoteAddrFunc func() net.Addr

	deadline *time.Timer
}

func (c *Conn) Write(b []byte) (int, error) {
	return c.writer.Write(b)
}

func (c *Conn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func (c *Conn) LocalAddr() net.Addr {
	if c.LocalAddrFunc != nil {
		return c.LocalAddrFunc()
	}
	return &net.TCPAddr{IP: net.IPv4zero, Port: 0}
}

func (c *Conn) RemoteAddr() net.Addr {
	if c.RemoteAddrFunc != nil {
		return c.RemoteAddrFunc()
	}
	return &net.TCPAddr{IP: net.IPv4zero, Port: 0}
}

func (c *Conn) Close() error {
	err := c.writer.Close()
	err2 := c.reader.Close()
	if c.onClose != nil {
		c.onClose()
	}
	return errors.Join(err, err2)
}

func (c *Conn) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.SetDeadline(t) }

func (c *Conn) SetDeadline(t time.Time) error {
	if t.IsZero() {
		if c.deadline != nil {
			c.deadline.Stop()
			c.deadline = nil
		}
		return nil
	}
	d := time.Until(t)
	if c.deadline != nil {
		c.deadline.Reset(d)
		return nil
	}
	c.deadline = time.AfterFunc(d, func() {
		c.Close()
	})
	return nil
}

// CloseWrite на сервере закрывает поток ответов (HTTP Response Body),
// сигнализируя клиенту об окончании данных (EOF) в Downlink-потоке.
func (c *Conn) CloseWrite() error {
	if c.writer != nil {
		// writer на сервере — это httpServerConn.
		// Его метод Close() закрывает тело ответа и делает Flush.
		return c.writer.Close()
	}
	return nil
}
