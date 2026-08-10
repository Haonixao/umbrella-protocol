package xhttp

import (
	"math/rand"
	"net/http"
	"strconv"
	"strings"
)

// Range помогает работать с диапазонами чисел (например, для паддинга)
type Range struct {
	Min int
	Max int
}

func (r Range) Rand() int {
	if r.Min >= r.Max {
		return r.Min
	}
	return r.Min + rand.Intn(r.Max-r.Min+1)
}

// ParseRange превращает строку "32-512" в структуру Range
func ParseRange(s string, fallback string) (Range, error) {
	val := strings.TrimSpace(s)
	if val == "" {
		val = fallback
	}
	parts := strings.Split(val, "-")
	if len(parts) == 1 {
		v, err := strconv.Atoi(parts[0])
		if err != nil {
			return Range{}, err
		}
		return Range{v, v}, nil
	}
	minVal, _ := strconv.Atoi(strings.TrimSpace(parts[0]))
	maxVal, _ := strconv.Atoi(strings.TrimSpace(parts[1]))
	return Range{minVal, maxVal}, nil
}

// Meta — то, что нужно серверу для работы сессии xhttp
type XMeta struct {
	SessionID string
	Seq       uint64
}

// ExtractXMeta упрощенно достает ID и Seq из заголовков
func ExtractXMeta(r *http.Request) XMeta {
	seq, _ := strconv.ParseUint(r.Header.Get("X-Seq"), 10, 64)
	return XMeta{
		SessionID: r.Header.Get("X-Session-ID"),
		Seq:       seq,
	}
}
