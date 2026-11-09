package auth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateToken(t *testing.T) {
	token, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken devolvió error: %v", err)
	}
	if len(token) < 40 {
		t.Errorf("el token es demasiado corto: %d caracteres", len(token))
	}
	if token[:4] != TokenPrefix {
		t.Errorf("el token debería empezar por %s: %s", TokenPrefix, token)
	}

	otro, _ := GenerateToken()
	if token == otro {
		t.Error("dos tokens deberían ser distintos")
	}
}

func TestHashYVerify(t *testing.T) {
	token, _ := GenerateToken()
	hash := HashToken(token)

	if hash != HashToken(token) {
		t.Error("el hash debería ser determinista")
	}
	if len(hash) != 64 {
		t.Errorf("se esperaba un hash SHA-256 en hexadecimal (64 chars), se obtuvo %d", len(hash))
	}

	if err := VerifyToken(hash, token); err != nil {
		t.Errorf("el token válido debería verificarse: %v", err)
	}
	if err := VerifyToken(hash, token+"x"); err == nil {
		t.Error("un token alterado no debería verificarse")
	}
	if err := VerifyToken("", token); err == nil {
		t.Error("un hash vacío no debería aceptarse")
	}
}

func TestWriteYReadTokenHash(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "token.hash")

	token, _ := GenerateToken()
	if err := WriteTokenHash(path, token); err != nil {
		t.Fatalf("WriteTokenHash devolvió error: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("no se creó el archivo: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("permisos: se esperaba 0600, se obtuvo %o", perm)
	}

	hash, err := ReadTokenHash(path)
	if err != nil {
		t.Fatalf("ReadTokenHash devolvió error: %v", err)
	}
	if hash != HashToken(token) {
		t.Error("el hash leído no coincide")
	}

	if _, err := ReadTokenHash(filepath.Join(dir, "inexistente")); err == nil {
		t.Error("se esperaba un error al leer un archivo inexistente")
	}
}

func TestWriteYReadPlainToken(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")

	token, _ := GenerateToken()
	if err := WritePlainToken(path, token); err != nil {
		t.Fatalf("WritePlainToken devolvió error: %v", err)
	}

	info, _ := os.Stat(path)
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("permisos: se esperaba 0600, se obtuvo %o", perm)
	}

	read, err := ReadPlainToken(path)
	if err != nil {
		t.Fatalf("ReadPlainToken devolvió error: %v", err)
	}
	if read != token {
		t.Error("el token leído no coincide")
	}
}

func TestReadPlainTokenUsaEntorno(t *testing.T) {
	t.Setenv("PORTS_TUI_TOKEN", "ptk_desde_entorno")

	token, err := ReadPlainToken(filepath.Join(t.TempDir(), "no-existe"))
	if err != nil {
		t.Fatalf("ReadPlainToken devolvió error: %v", err)
	}
	if token != "ptk_desde_entorno" {
		t.Errorf("se esperaba el token del entorno, se obtuvo %s", token)
	}
}

func TestEnsureSelfSignedCert(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls", "cert.pem")
	keyPath := filepath.Join(dir, "tls", "key.pem")

	if err := EnsureSelfSignedCert(certPath, keyPath, []string{"mi-host.local"}, 0); err != nil {
		t.Fatalf("EnsureSelfSignedCert devolvió error: %v", err)
	}

	fingerprint, err := CertFingerprint(certPath)
	if err != nil {
		t.Fatalf("CertFingerprint devolvió error: %v", err)
	}
	if len(fingerprint) != 64 {
		t.Errorf("huella inesperada: %s", fingerprint)
	}

	// Regenerar no debe fallar si ya existe.
	if err := EnsureSelfSignedCert(certPath, keyPath, nil, 0); err != nil {
		t.Fatalf("la segunda llamada falló: %v", err)
	}
}
