package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// TLSConfig describe el material criptográfico del daemon.
type TLSConfig struct {
	CertPath string
	KeyPath  string
}

// EnsureSelfSignedCert genera un certificado auto-firmado si no existe.
//
// El certificado se emite como CA propia (IsCA + KeyUsageCertSign) para que
// el cliente pueda usarlo como raíz de confianza y así fijar la identidad
// del daemon sin depender de una autoridad externa.
func EnsureSelfSignedCert(certPath, keyPath string, extraHosts []string, validFor time.Duration) error {
	if certExists(certPath) && certExists(keyPath) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("no se pudo generar la clave: %w", err)
	}

	hosts := localHosts(extraHosts)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("no se pudo generar el serial: %w", err)
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"ports-tui"},
			CommonName:   "ports-tui daemon",
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(validFor),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              hosts.dns,
		IPAddresses:           hosts.ips,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("no se pudo crear el certificado: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return err
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return os.WriteFile(keyPath, keyPEM, 0o600)
}

// CertFingerprint devuelve el SHA-256 del certificado DER en hex, el mismo
// valor que muestra `openssl x509 -fingerprint -sha256`. Sirve para verificar
// la identidad del daemon por fuera de banda.
func CertFingerprint(certPath string) (string, error) {
	data, err := os.ReadFile(certPath)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return "", fmt.Errorf("certificado PEM inválido: %s", certPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:]), nil
}

func certExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir() && info.Size() > 0
}

type hostSet struct {
	dns []string
	ips []net.IP
}

// localHosts arma el SAN del certificado: localhost, loopbacks, hostname e
// IPs de las interfaces locales.
func localHosts(extra []string) hostSet {
	set := hostSet{dns: []string{"localhost"}}
	seenDNS := map[string]bool{"localhost": true}
	seenIP := map[string]bool{}

	addIP := func(ip net.IP) {
		if ip == nil || ip.IsUnspecified() {
			return
		}
		key := ip.String()
		if !seenIP[key] {
			seenIP[key] = true
			set.ips = append(set.ips, ip)
		}
	}

	addIP(net.ParseIP("127.0.0.1"))
	addIP(net.ParseIP("::1"))

	if host, err := os.Hostname(); err == nil && host != "" {
		if !seenDNS[host] {
			seenDNS[host] = true
			set.dns = append(set.dns, host)
		}
	}

	addrs, err := net.InterfaceAddrs()
	if err == nil {
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				addIP(ipnet.IP)
			}
		}
	}

	for _, h := range extra {
		h = trimSpace(h)
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			addIP(ip)
			continue
		}
		if !seenDNS[h] {
			seenDNS[h] = true
			set.dns = append(set.dns, h)
		}
	}

	return set
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}
