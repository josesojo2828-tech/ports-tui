package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/josesojo2828-tech/ports-tui/internal/audit"
	"github.com/josesojo2828-tech/ports-tui/internal/auth"
	"github.com/josesojo2828-tech/ports-tui/internal/firewall"
	"github.com/josesojo2828-tech/ports-tui/internal/ufw"
)

// newTestServer levanta un servidor con el backend simulado.
func newTestServer(t *testing.T, token string) (*Server, *ufw.Fake, *audit.Logger) {
	t.Helper()

	backend := ufw.NewFake()
	logger, err := audit.NewLogger("")
	if err != nil {
		t.Fatalf("no se pudo crear el logger: %v", err)
	}

	server := NewServer(Options{
		Service:   firewall.NewService(backend),
		TokenHash: auth.HashToken(token),
		Audit:     logger,
		Version:   "test",
	})
	return server, backend, logger
}

// request ejecuta una petición contra el handler.
func request(t *testing.T, server *Server, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()

	var reader *bytes.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("no se pudo serializar el cuerpo: %v", err)
		}
		reader = bytes.NewReader(data)
	} else {
		reader = bytes.NewReader(nil)
	}

	req := httptest.NewRequest(method, path, reader)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	return rec
}

func TestHealthEsPublico(t *testing.T) {
	server, _, _ := newTestServer(t, "token-secreto")

	rec := request(t, server, http.MethodGet, "/api/v1/health", "", nil)
	if rec.Code != http.StatusOK {
		t.Errorf("código: se esperaba 200, se obtuvo %d", rec.Code)
	}
}

func TestSnapshotExigeToken(t *testing.T) {
	server, _, _ := newTestServer(t, "token-secreto")

	rec := request(t, server, http.MethodGet, "/api/v1/snapshot", "", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("código: se esperaba 401, se obtuvo %d", rec.Code)
	}

	rec = request(t, server, http.MethodGet, "/api/v1/snapshot", "token-incorrecto", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("código con token incorrecto: se esperaba 401, se obtuvo %d", rec.Code)
	}

	rec = request(t, server, http.MethodGet, "/api/v1/snapshot", "token-secreto", nil)
	if rec.Code != http.StatusOK {
		t.Errorf("código con token válido: se esperaba 200, se obtuvo %d (cuerpo: %s)", rec.Code, rec.Body.String())
	}
}

func TestCabeceraAuthorizationInvalida(t *testing.T) {
	server, _, _ := newTestServer(t, "token-secreto")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/snapshot", nil)
	req.Header.Set("Authorization", "Basic token-secreto")

	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("código: se esperaba 401, se obtuvo %d", rec.Code)
	}
}

func TestCrearRegla(t *testing.T) {
	server, backend, logger := newTestServer(t, "token-secreto")

	body := map[string]string{
		"port":    "8080",
		"proto":   "tcp",
		"from":    "any",
		"action":  "allow",
		"comment": "prueba",
	}

	rec := request(t, server, http.MethodPost, "/api/v1/rules", "token-secreto", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("código: se esperaba 201, se obtuvo %d (cuerpo: %s)", rec.Code, rec.Body.String())
	}

	rules, err := backend.Rules(t.Context())
	if err != nil {
		t.Fatalf("no se pudieron leer las reglas: %v", err)
	}
	found := false
	for _, r := range rules {
		if r.Target.Port == "8080" && r.Comment == "prueba" {
			found = true
		}
	}
	if !found {
		t.Error("la regla 8080 no se creó en el backend")
	}

	entries := logger.Recent(10)
	if len(entries) == 0 {
		t.Fatal("no se registró la acción en la auditoría")
	}
	if entries[0].Action != "rule.add" {
		t.Errorf("acción auditada: se esperaba rule.add, se obtuvo %s", entries[0].Action)
	}
}

func TestCrearReglaInvalida(t *testing.T) {
	server, backend, _ := newTestServer(t, "token-secreto")

	body := map[string]string{"port": "99999", "proto": "tcp", "action": "allow"}
	rec := request(t, server, http.MethodPost, "/api/v1/rules", "token-secreto", body)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("código: se esperaba 400, se obtuvo %d", rec.Code)
	}

	rules, _ := backend.Rules(t.Context())
	for _, r := range rules {
		if r.Target.Port == "99999" {
			t.Error("una regla inválida no debe llegar al backend")
		}
	}
}

func TestEliminarRegla(t *testing.T) {
	server, backend, _ := newTestServer(t, "token-secreto")

	rules, _ := backend.Rules(t.Context())
	if len(rules) == 0 {
		t.Fatal("no hay reglas iniciales")
	}
	target := rules[0].Number

	rec := request(t, server, http.MethodDelete, "/api/v1/rules/"+itoa(target), "token-secreto", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("código: se esperaba 200, se obtuvo %d", rec.Code)
	}

	rules, _ = backend.Rules(t.Context())
	for _, r := range rules {
		if r.Number == target {
			t.Error("la regla no se eliminó")
		}
	}
}

func TestEliminarReglaInvalida(t *testing.T) {
	server, _, _ := newTestServer(t, "token-secreto")

	rec := request(t, server, http.MethodDelete, "/api/v1/rules/abc", "token-secreto", nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("código: se esperaba 400, se obtuvo %d", rec.Code)
	}
}

func TestActivarDesactivarFirewall(t *testing.T) {
	server, backend, _ := newTestServer(t, "token-secreto")

	rec := request(t, server, http.MethodPost, "/api/v1/ufw/disable", "token-secreto", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("código: se esperaba 200, se obtuvo %d", rec.Code)
	}

	status, _ := backend.Status(t.Context())
	if status.Active {
		t.Error("el firewall simulado debería estar inactivo")
	}

	rec = request(t, server, http.MethodPost, "/api/v1/ufw/enable", "token-secreto", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("código: se esperaba 200, se obtuvo %d", rec.Code)
	}
	status, _ = backend.Status(t.Context())
	if !status.Active {
		t.Error("el firewall simulado debería estar activo")
	}
}

func TestMetodoNoPermitido(t *testing.T) {
	server, _, _ := newTestServer(t, "token-secreto")

	rec := request(t, server, http.MethodGet, "/api/v1/ufw/enable", "token-secreto", nil)
	if rec.Code != http.StatusMethodNotAllowed && rec.Code != http.StatusNotFound {
		t.Errorf("código: se esperaba 404 o 405, se obtuvo %d", rec.Code)
	}
}

func TestLimiteDeFallosDeAutenticacion(t *testing.T) {
	server, _, _ := newTestServer(t, "token-secreto")

	for i := 0; i < maxFailures; i++ {
		request(t, server, http.MethodGet, "/api/v1/snapshot", "incorrecto", nil)
	}

	rec := request(t, server, http.MethodGet, "/api/v1/snapshot", "token-secreto", nil)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("código: se esperaba 429 tras %d fallos, se obtuvo %d", maxFailures, rec.Code)
	}
}

// itoa convierte un entero en cadena.
func itoa(value int) string {
	return strconv.Itoa(value)
}
