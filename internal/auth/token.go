// Package auth implementa la autenticación por token Bearer de la API.
//
// El daemon nunca guarda el token en claro: almacena su hash SHA-256 en un
// archivo con permisos 0600. El cliente guarda el token en claro en su home
// (0600) porque necesita presentarlo en cada request.
//
// El token es una cadena aleatoria de 256 bits (32 bytes) con prefijo "ptk_".
// La entropía alta hace innecesario un KDF costoso: un atacante con el hash
// no puede invertirlo por fuerza bruta. La comparación se hace en tiempo
// constante para no filtrar información por temporización.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// TokenPrefix identifica los tokens de ports-tui.
const TokenPrefix = "ptk_"

// tokenBytes es la entropía del token: 256 bits.
const tokenBytes = 32

// ErrTokenInvalid se devuelve cuando el token presentado no coincide.
var ErrTokenInvalid = errors.New("token inválido")

// ErrNotFound indica que el archivo solicitado no existe.
var ErrNotFound = errors.New("archivo no encontrado")

// GenerateToken devuelve un token nuevo con 256 bits de entropía.
func GenerateToken() (string, error) {
	buf := make([]byte, tokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("no se pudo generar el token: %w", err)
	}
	return TokenPrefix + base64.RawURLEncoding.EncodeToString(buf), nil
}

// HashToken devuelve el hash SHA-256 del token en hexadecimal.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// VerifyToken compara el token presentado con el hash almacenado en tiempo
// constante. Devuelve ErrTokenInvalid cuando no coinciden.
func VerifyToken(storedHash, presented string) error {
	if storedHash == "" {
		return ErrTokenInvalid
	}
	presentedHash := HashToken(presented)
	if subtle.ConstantTimeCompare([]byte(storedHash), []byte(presentedHash)) != 1 {
		return ErrTokenInvalid
	}
	return nil
}

// WriteTokenHash guarda el hash del token con permisos 0600.
func WriteTokenHash(path, token string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(HashToken(token)+"\n"), 0o600)
}

// ReadTokenHash lee el hash del token almacenado.
func ReadTokenHash(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", ErrNotFound
		}
		return "", err
	}
	hash := strings.TrimSpace(string(data))
	if hash == "" {
		return "", ErrNotFound
	}
	return hash, nil
}

// WritePlainToken guarda el token en claro (archivo del cliente) con 0600.
func WritePlainToken(path, token string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(token+"\n"), 0o600)
}

// ReadPlainToken lee el token en claro del cliente. Si el archivo no existe
// recurre a la variable de entorno PORTS_TUI_TOKEN.
func ReadPlainToken(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		token := strings.TrimSpace(string(data))
		if token != "" {
			return token, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if token := strings.TrimSpace(os.Getenv("PORTS_TUI_TOKEN")); token != "" {
		return token, nil
	}
	return "", ErrNotFound
}
