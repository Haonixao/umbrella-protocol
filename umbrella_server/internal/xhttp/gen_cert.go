package xhttp

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"
)

func GenCertInMemory(dest string) (certPEM []byte, keyPEM []byte, err error) {
	// 1. Generate Root CA
	caPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubBytes, _ := x509.MarshalPKIXPublicKey(&caPriv.PublicKey)
	skid := sha1.Sum(pubBytes)

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Umbrella Local CA"},
			CommonName:   "Umbrella Root CA",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		SubjectKeyId:          skid[:],
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caPriv.PublicKey, caPriv)
	if err != nil {
		return nil, nil, err
	}

	// 2. Generate Server Cert (sni)
	servPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	servPubBytes, _ := x509.MarshalPKIXPublicKey(&servPriv.PublicKey)
	servSkid := sha1.Sum(servPubBytes)

	sni, _, err := net.SplitHostPort(dest)
	if err != nil {
		return nil, nil, err
	}

	servTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Umbrella Server"},
			CommonName:   sni,
		},
		DNSNames:       []string{sni, "*." + sni},
		NotBefore:      time.Now().Add(-1 * time.Hour),
		NotAfter:       time.Now().AddDate(1, 0, 0),
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		SubjectKeyId:   servSkid[:],
		AuthorityKeyId: skid[:],
	}

	servBytes, err := x509.CreateCertificate(rand.Reader, servTemplate, caTemplate, &servPriv.PublicKey, caPriv)
	if err != nil {
		return nil, nil, err
	}

	// --- КОДИРОВАНИЕ В PEM (в памяти) ---

	// Собираем цепочку сертификатов: [Leaf] + [Root]
	certBuf := new(bytes.Buffer)
	pem.Encode(certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: servBytes})
	pem.Encode(certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: caBytes})

	// Кодируем приватный ключ сервера
	keyBuf := new(bytes.Buffer)
	keyBytes, _ := x509.MarshalECPrivateKey(servPriv)
	pem.Encode(keyBuf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	return certBuf.Bytes(), keyBuf.Bytes(), nil
}
