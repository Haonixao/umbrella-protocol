package xhttp

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"
)

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
