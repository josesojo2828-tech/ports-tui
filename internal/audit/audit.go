// Package audit registra las acciones sensibles de la API en un log JSONL.
package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Entry es una acción registrada.
type Entry struct {
	Timestamp time.Time `json:"timestamp"`
	// Action describe la operación: "rule.add", "rule.delete", "ufw.enable"...
	Action string `json:"action"`
	// Target identifica el objeto afectado (puerto, regla, etc).
	Target string `json:"target"`
	// Result es "ok" o "error".
	Result string `json:"result"`
	// Detail añade contexto del error o del resultado.
	Detail string `json:"detail,omitempty"`
	// RemoteAddr es la IP que hizo la petición.
	RemoteAddr string `json:"remote_addr,omitempty"`
	// UserAgent identifica al cliente.
	UserAgent string `json:"user_agent,omitempty"`
}

// Logger escribe las entradas en un archivo y las mantiene en memoria.
type Logger struct {
	mu      sync.Mutex
	file    *os.File
	entries []Entry
	max     int
}

// NewLogger abre (o crea) el archivo de auditoría.
//
// Si no se puede abrir el archivo, el logger sigue funcionando en memoria y
// las entradas se pierden al reiniciar; esto permite ejecutar el daemon en
// modo demo sin permisos de root.
func NewLogger(path string) (*Logger, error) {
	logger := &Logger{max: 200}

	if path == "" {
		return logger, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return logger, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return logger, err
	}
	logger.file = file
	return logger, nil
}

// Log registra una acción.
func (l *Logger) Log(entry Entry) {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.entries = append(l.entries, entry)
	if len(l.entries) > l.max {
		l.entries = l.entries[len(l.entries)-l.max:]
	}

	if l.file == nil {
		return
	}
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	l.file.Write(append(data, '\n'))
}

// Recent devuelve las últimas entradas, de la más reciente a la más antigua.
func (l *Logger) Recent(limit int) []Entry {
	l.mu.Lock()
	defer l.mu.Unlock()

	if limit <= 0 || limit > len(l.entries) {
		limit = len(l.entries)
	}
	out := make([]Entry, 0, limit)
	for i := len(l.entries) - 1; i >= 0 && len(out) < limit; i-- {
		out = append(out, l.entries[i])
	}
	return out
}

// Close cierra el archivo de auditoría.
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	return err
}
