package xhttp

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"sync"
)

// CopyBufPool holds reusable 32 KiB buffers.
var CopyBufPool = sync.Pool{New: func() any { b := make([]byte, 32*1024); return &b }}

// UDPBufPool holds reusable buffers large enough for max UDP packet + Torrent headers.
var UDPBufPool = sync.Pool{New: func() any { b := make([]byte, 66*1024); return &b }}

// getRandomInt возвращает случайное число в диапазоне [min, max)
func getRandomInt(min, max int) int {
	if max <= min {
		return min
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max-min)))
	return min + int(n.Int64())
}

// generateRandomString создает hex-строку случайной длины для X-Padding
func generateRandomString(min, max int) string {
	size := getRandomInt(min, max)
	b := make([]byte, size/2)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
