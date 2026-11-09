// Package config centraliza rutas, direcciones y valores por defecto de
// ports-tui. La configuración del daemon vive en /etc/ports-tui y la del
// cliente (TUI) en ~/.config/ports-tui.
package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

const (
	// AppName identifica la herramienta en logs, systemd y la UI.
	AppName = "ports-tui"

	// DefaultAddr es la dirección de escucha por defecto: solo local.
	DefaultAddr = "127.0.0.1:9443"
	// DefaultClientServer es la URL base que usa la TUI para hablar al daemon.
	DefaultClientServer = "https://127.0.0.1:9443"

	// SystemDir contiene la configuración protegida del daemon (root).
	SystemDir = "/etc/ports-tui"
	// StateDir contiene datos de estado (TLS, hashes de token).
	StateDir = "/var/lib/ports-tui"
	// LogDir contiene el audit log.
	LogDir = "/var/log/ports-tui"

	// DefaultTLSCert y DefaultTLSKey son el par de certificados auto-firmados.
	DefaultTLSCert = "/etc/ports-tui/tls/cert.pem"
	DefaultTLSKey  = "/etc/ports-tui/tls/key.pem"
	// DefaultTokenHash guarda el hash SHA-256 del token del daemon.
	DefaultTokenHash = "/etc/ports-tui/token.hash"
	// DefaultAuditLog es el destino del registro de auditoría.
	DefaultAuditLog = "/var/log/ports-tui/audit.log"
)

// Version es la versión del binario. Se sobreescribe en build con
// -ldflags "-X github.com/josesojo2828-tech/ports-tui/internal/config.Version=x.y.z".
var Version = "0.1.0"

// ErrNotFound indica que un archivo opcional no existe.
var ErrNotFound = errors.New("archivo no encontrado")

// DaemonConfig es la configuración del servicio root.
type DaemonConfig struct {
	// ListenAddr es la dirección TCP donde se publica la API y el dashboard.
	ListenAddr string `json:"listen_addr"`
	// TLSCert y TLSKey apuntan al par de certificados. Si están vacíos se
	// genera un certificado auto-firmado en tiempo de arranque.
	TLSCert string `json:"tls_cert"`
	TLSKey  string `json:"tls_key"`
	// TokenHashFile guarda el hash del token requerido por la API.
	TokenHashFile string `json:"token_hash_file"`
	// AuditLog es el archivo JSONL donde se registran las acciones.
	AuditLog string `json:"audit_log"`
	// CORSOrigin vacío desactiva CORS (la UI se sirve en el mismo origen).
	CORSOrigin string `json:"cors_origin"`
	// Demo activa el backend de ufw simulado, sin tocar el sistema real.
	Demo bool `json:"demo"`
}

// ClientConfig es la configuración local de la TUI.
type ClientConfig struct {
	// Server es la URL base del daemon.
	Server string `json:"server"`
	// CACert es el certificado usado para validar el TLS del daemon.
	// Vacío = validación del sistema. "insecure" = sin validar.
	CACert string `json:"ca_cert"`
	// TokenFile guarda el token en claro del cliente.
	TokenFile string `json:"token_file"`
	// Insecure omite la validación TLS (solo para pruebas).
	Insecure bool `json:"insecure"`
}

// DefaultDaemonConfig devuelve la configuración de fábrica del daemon.
func DefaultDaemonConfig() DaemonConfig {
	return DaemonConfig{
		ListenAddr:    DefaultAddr,
		TLSCert:       DefaultTLSCert,
		TLSKey:        DefaultTLSKey,
		TokenHashFile: DefaultTokenHash,
		AuditLog:      DefaultAuditLog,
	}
}

// DefaultClientConfig devuelve la configuración de fábrica del cliente,
// resuelta en el home del usuario actual.
func DefaultClientConfig() ClientConfig {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return ClientConfig{
		Server:    DefaultClientServer,
		CACert:    DefaultTLSCert,
		TokenFile: filepath.Join(home, ".config", AppName, "token"),
	}
}

// DaemonConfigPath es la ruta del archivo de configuración del daemon.
func DaemonConfigPath() string { return filepath.Join(SystemDir, "config.json") }

// ClientConfigPath es la ruta del archivo de configuración del cliente.
func ClientConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".config", AppName, "config.json")
}

// LoadDaemonConfig lee la configuración del daemon y aplica los defaults
// para los campos ausentes. Si el archivo no existe devuelve los defaults.
func LoadDaemonConfig(path string) (DaemonConfig, error) {
	cfg := DefaultDaemonConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return cfg, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = DefaultAddr
	}
	if cfg.TokenHashFile == "" {
		cfg.TokenHashFile = DefaultTokenHash
	}
	if cfg.AuditLog == "" {
		cfg.AuditLog = DefaultAuditLog
	}
	return cfg, nil
}

// LoadClientConfig lee la configuración del cliente y aplica los defaults.
func LoadClientConfig(path string) (ClientConfig, error) {
	cfg := DefaultClientConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return cfg, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	if cfg.Server == "" {
		cfg.Server = DefaultClientServer
	}
	if cfg.TokenFile == "" {
		cfg.TokenFile = DefaultClientConfig().TokenFile
	}
	return cfg, nil
}

// SaveDaemonConfig escribe la configuración del daemon con permisos 0600.
func SaveDaemonConfig(path string, cfg DaemonConfig) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return writeJSON(path, cfg, 0o600)
}

// SaveClientConfig escribe la configuración del cliente con permisos 0600.
func SaveClientConfig(path string, cfg ClientConfig) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return writeJSON(path, cfg, 0o600)
}

func writeJSON(path string, v any, perm os.FileMode) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, perm)
}

// ExpandPath expande "~" al home del usuario.
func ExpandPath(path string) string {
	if path == "" {
		return path
	}
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, strings.TrimPrefix(path, "~"))
		}
	}
	return path
}
