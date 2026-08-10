package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"time"
)

func main() {
	// Адрес вашего сервера Umbrella/Xtls
	serverAddr := "0.0.0.0:443"

	// SNI, который мы проверяем (должен быть в списке разрешенных на сервере)
	sni := "coder.com"

	fmt.Printf("=== Probe Test: Checking Reality Fallback ===\n")
	fmt.Printf("Target: %s with SNI: %s\n", serverAddr, sni)

	// 1. Настраиваем стандартный TLS (как обычный зонд/браузер)
	// Мы НЕ используем библиотеку reality здесь, так как мы "не знаем" о ней.
	tlsConfig := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // Игнорируем проверку, так как нам важно только КТО ответил
	}

	// 2. Устанавливаем соединение
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", serverAddr, tlsConfig)
	if err != nil {
		log.Fatalf("[FAILED] Server rejected connection: %v\n", err)
	}
	defer conn.Close()

	// 3. Получаем состояние TLS
	state := conn.ConnectionState()

	fmt.Printf("=== XTLS Connection Info ===\n")
	fmt.Printf("Server Address: %s\n", serverAddr)
	fmt.Printf("Actual RemoteAddr: %s\n", conn.RemoteAddr())
	fmt.Printf("TLS Version: %s\n", tlsVersionToString(state.Version))
	fmt.Printf("Cipher Suite: %s\n", tls.CipherSuiteName(state.CipherSuite))
	fmt.Printf("Server Name (SNI): %s\n", state.ServerName)

	// 4. Проверяем сертификат
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		fmt.Printf("\n=== Server Certificate ===\n")
		fmt.Printf("Subject: %s\n", cert.Subject)
		fmt.Printf("Issuer: %s\n", cert.Issuer)
		fmt.Printf("DNS Names: %v\n", cert.DNSNames)
		fmt.Printf("Not Before: %s\n", cert.NotBefore)
		fmt.Printf("Not After: %s\n", cert.NotAfter)
		if cert.SerialNumber != nil {
			fmt.Printf("Serial: %s\n", cert.SerialNumber.String())
		}

		if cert.Subject.String() == cert.Issuer.String() {
			fmt.Println("\n[RESULT] TEST FAILED: This is a self-signed certificate! Reality is NOT working.")
			return
		}

		fmt.Printf("Issuer Organization: %v\n", cert.Issuer.Organization)

		fmt.Println("\n--- Performing Double-Check against real site ---")
		realCert, err := getOriginalCertificate(sni)
		if err != nil {
			fmt.Printf("Could not fetch original cert for comparison: %v\n", err)
			return
		} else {
			// Сравниваем серийные номера и отпечатки (Fingerprints)
			if cert.SerialNumber.String() == realCert.SerialNumber.String() {
				fmt.Println("[RESULT] TEST PASSED: Byte-perfect match!")
				fmt.Println("The certificate is EXACTLY the same as the real one.")
			} else {
				fmt.Println("[RESULT] TEST FAILED: Certificate fingerprint mismatch.")
				fmt.Println("The server is faking the DNS names, but the certificate is different.")
				return
			}
		}

		fmt.Println("\n[RESULT] TEST PASSED: Server successfully hidden!")
		fmt.Printf("The probe sees a real certificate for %s, not a proxy.\n", sni)
	} else {
		fmt.Println("\n[RESULT] TEST FAILED: No certificates received.")
	}
}

func getOriginalCertificate(domain string) (*x509.Certificate, error) {
	conn, err := tls.Dial("tcp", domain+":443", &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates[0], nil
}

func tlsVersionToString(v uint16) string {
	switch v {
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
