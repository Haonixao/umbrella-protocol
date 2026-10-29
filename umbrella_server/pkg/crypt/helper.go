package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
)

// deriveKey creates a 32-byte key from the secret using SHA-256.
func deriveKey(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

// Encrypt encrypts a message using a secret.
// It derives a key with SHA-256, uses AES-256-GCM, and returns
// base64( nonce || ciphertext ) as the result string.
func Encrypt(msg string, secret string) (string, error) {
	if len(msg) == 0 {
		return "", errors.New("crypt: message must not be empty")
	}
	if secret == "" {
		return "", errors.New("crypt: secret must not be empty")
	}

	key := deriveKey(secret)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(msg), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts a message encrypted with Encrypt using the same secret.
func Decrypt(encrypted string, secret string) (string, error) {
	if encrypted == "" {
		return "", errors.New("crypt: encrypted value must not be empty")
	}
	if secret == "" {
		return "", errors.New("crypt: secret must not be empty")
	}

	data, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}

	key := deriveKey(secret)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("crypt: malformed ciphertext")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
