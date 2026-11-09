// Package api expone la API REST de ports-tui.
//
// Todos los endpoints salvo /api/v1/health exigen un token Bearer. La
// comparación del token es en tiempo constante y los fallos repetidos desde
// una misma IP bloquean temporalmente esa IP.
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/josesojo2828-tech/ports-tui/internal/audit"
	"github.com/josesojo2828-tech/ports-tui/internal/auth"
	"github.com/josesojo2828-tech/ports-tui/internal/firewall"
	"github.com/josesojo2828-tech/ports-tui/internal/ufw"
)

// Opciones de configuración del servidor.
type Options struct {
	// Service es el servicio de análisis de puertos.
	Service *firewall.Service
	// TokenHash es el hash SHA-256 del token aceptado.
	TokenHash string
	// Audit registra las acciones mutantes.
	Audit *audit.Logger
	// CORSOrigin habilita CORS para ese origen (vacío = deshabilitado).
	CORSOrigin string
	// Version se expone en /health.
	Version string
}

// Server implementa el router de la API.
type Server struct {
	svc        *firewall.Service
	tokenHash  string
	audit      *audit.Logger
	corsOrigin string
	version    string
	mux        *http.ServeMux
	limiter    *failureLimiter
}

// NewServer construye el servidor y registra las rutas.
func NewServer(opts Options) *Server {
	s := &Server{
		svc:        opts.Service,
		tokenHash:  opts.TokenHash,
		audit:      opts.Audit,
		corsOrigin: opts.CORSOrigin,
		version:    opts.Version,
		mux:        http.NewServeMux(),
		limiter:    newFailureLimiter(),
	}

	s.routes()
	return s
}

// Handler devuelve el handler completo de la API.
func (s *Server) Handler() http.Handler {
	return s.securityHeaders(s.mux)
}

// routes registra los endpoints de la API v1.
func (s *Server) routes() {
	s.mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	s.mux.HandleFunc("GET /api/v1/status", s.protected(s.handleStatus))
	s.mux.HandleFunc("GET /api/v1/snapshot", s.protected(s.handleSnapshot))
	s.mux.HandleFunc("GET /api/v1/ports", s.protected(s.handlePorts))
	s.mux.HandleFunc("GET /api/v1/rules", s.protected(s.handleRules))
	s.mux.HandleFunc("POST /api/v1/rules", s.protected(s.handleCreateRule))
	s.mux.HandleFunc("DELETE /api/v1/rules/{number}", s.protected(s.handleDeleteRule))
	s.mux.HandleFunc("POST /api/v1/rules/{number}/enable", s.protected(s.handleEnableRule))
	s.mux.HandleFunc("POST /api/v1/rules/{number}/disable", s.protected(s.handleDisableRule))
	s.mux.HandleFunc("POST /api/v1/ufw/enable", s.protected(s.handleUFWEnable))
	s.mux.HandleFunc("POST /api/v1/ufw/disable", s.protected(s.handleUFWDisable))
	s.mux.HandleFunc("POST /api/v1/ufw/reload", s.protected(s.handleUFWReload))
	s.mux.HandleFunc("GET /api/v1/audit", s.protected(s.handleAudit))
}

// handleHealth responde el estado del servicio. Es público y no revela datos.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"version": s.version,
		"time":    time.Now().Format(time.RFC3339),
	})
}

// handleStatus devuelve estado del firewall y métricas.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	snapshot, err := s.svc.Snapshot(r.Context())
	if err != nil {
		s.fail(w, r, "status", "", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"hostname":     snapshot.Hostname,
		"backend":      snapshot.Backend,
		"ufw":          snapshot.UFW,
		"summary":      snapshot.Summary,
		"generated_at": snapshot.GeneratedAt,
	})
}

// handleSnapshot devuelve la vista completa: puertos, reglas y exposición.
func (s *Server) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	snapshot, err := s.svc.Snapshot(r.Context())
	if err != nil {
		s.fail(w, r, "snapshot", "", err)
		return
	}
	writeJSON(w, http.StatusOK, snapshot)
}

// handlePorts devuelve los sockets que escuchan con su estado de exposición.
func (s *Server) handlePorts(w http.ResponseWriter, r *http.Request) {
	snapshot, err := s.svc.Snapshot(r.Context())
	if err != nil {
		s.fail(w, r, "ports", "", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"listeners": snapshot.Listeners,
		"exposure":  snapshot.Exposure,
		"summary":   snapshot.Summary,
	})
}

// handleRules devuelve las reglas de UFW.
func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	rules, err := s.svc.Backend().Rules(r.Context())
	if err != nil {
		s.fail(w, r, "rules.list", "", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rules": rules})
}

// ruleRequest es el cuerpo de POST /api/v1/rules.
type ruleRequest struct {
	Port    string `json:"port"`
	Proto   string `json:"proto"`
	From    string `json:"from"`
	Action  string `json:"action"`
	Comment string `json:"comment"`
}

// handleCreateRule crea una regla nueva.
func (s *Server) handleCreateRule(w http.ResponseWriter, r *http.Request) {
	var req ruleRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	spec := ufw.Spec{
		Port:    req.Port,
		Proto:   req.Proto,
		From:    req.From,
		Action:  req.Action,
		Comment: req.Comment,
	}
	if err := spec.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := s.svc.Backend().Add(r.Context(), spec); err != nil {
		s.fail(w, r, "rule.add", spec.Describe(), err)
		return
	}

	s.record(r, "rule.add", spec.Describe(), "ok", "")
	writeJSON(w, http.StatusCreated, map[string]any{
		"status": "ok",
		"rule":   spec.Normalize(),
	})
}

// handleDeleteRule elimina una regla por número.
func (s *Server) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	number, err := ruleNumber(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := s.svc.Backend().Delete(r.Context(), number); err != nil {
		s.fail(w, r, "rule.delete", strconv.Itoa(number), err)
		return
	}

	s.record(r, "rule.delete", strconv.Itoa(number), "ok", "")
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "deleted": number})
}

// handleEnableRule habilita una regla.
func (s *Server) handleEnableRule(w http.ResponseWriter, r *http.Request) {
	s.setRuleEnabled(w, r, true)
}

// handleDisableRule deshabilita una regla.
func (s *Server) handleDisableRule(w http.ResponseWriter, r *http.Request) {
	s.setRuleEnabled(w, r, false)
}

func (s *Server) setRuleEnabled(w http.ResponseWriter, r *http.Request, enabled bool) {
	number, err := ruleNumber(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if err := s.svc.Backend().SetRuleEnabled(r.Context(), number, enabled); err != nil {
		action := "rule.disable"
		if enabled {
			action = "rule.enable"
		}
		s.fail(w, r, action, strconv.Itoa(number), err)
		return
	}

	action := "rule.disable"
	if enabled {
		action = "rule.enable"
	}
	s.record(r, action, strconv.Itoa(number), "ok", "")
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"rule":    number,
		"enabled": enabled,
	})
}

// handleUFWEnable habilita el firewall completo.
func (s *Server) handleUFWEnable(w http.ResponseWriter, r *http.Request) {
	s.setFirewallEnabled(w, r, true)
}

// handleUFWDisable deshabilita el firewall completo.
func (s *Server) handleUFWDisable(w http.ResponseWriter, r *http.Request) {
	s.setFirewallEnabled(w, r, false)
}

func (s *Server) setFirewallEnabled(w http.ResponseWriter, r *http.Request, enabled bool) {
	if err := s.svc.Backend().SetEnabled(r.Context(), enabled); err != nil {
		s.fail(w, r, "ufw.enable", "", err)
		return
	}

	action := "ufw.disable"
	if enabled {
		action = "ufw.enable"
	}
	s.record(r, action, "", "ok", "")
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "enabled": enabled})
}

// handleUFWReload recarga las reglas de UFW.
func (s *Server) handleUFWReload(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.Backend().Reload(r.Context()); err != nil {
		s.fail(w, r, "ufw.reload", "", err)
		return
	}
	s.record(r, "ufw.reload", "", "ok", "")
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

// handleAudit devuelve las últimas acciones registradas.
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if s.audit == nil {
		writeJSON(w, http.StatusOK, map[string]any{"entries": []audit.Entry{}})
		return
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 && v <= 500 {
			limit = v
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": s.audit.Recent(limit)})
}

// record escribe una entrada de auditoría.
func (s *Server) record(r *http.Request, action, target, result, detail string) {
	if s.audit == nil {
		return
	}
	s.audit.Log(audit.Entry{
		Action:     action,
		Target:     target,
		Result:     result,
		Detail:     detail,
		RemoteAddr: r.RemoteAddr,
		UserAgent:  r.UserAgent(),
	})
}

// fail registra el error y lo devuelve al cliente.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, action, target string, err error) {
	s.record(r, action, target, "error", err.Error())
	writeError(w, http.StatusInternalServerError, err.Error())
}

// ruleNumber extrae y valida el número de regla de la ruta.
func ruleNumber(r *http.Request) (int, error) {
	raw := r.PathValue("number")
	number, err := strconv.Atoi(raw)
	if err != nil || number <= 0 {
		return 0, fmt.Errorf("número de regla inválido: %s", raw)
	}
	return number, nil
}

// writeJSON escribe una respuesta JSON.
func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

// writeError escribe un error JSON.
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

// decodeJSON lee un cuerpo JSON con límite de tamaño.
func decodeJSON(r *http.Request, dst any) error {
	const maxBody = 64 << 10
	r.Body = http.MaxBytesReader(nil, r.Body, maxBody)

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		if errors.Is(err, http.ErrBodyReadAfterClose) {
			return fmt.Errorf("cuerpo de la petición inválido")
		}
		return fmt.Errorf("cuerpo de la petición inválido: %w", err)
	}
	return nil
}

// BearerToken extrae el token de la cabecera Authorization.
func BearerToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if header == "" {
		return ""
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

// verifyToken delega en el paquete auth la comparación en tiempo constante.
func (s *Server) verifyToken(presented string) error {
	return auth.VerifyToken(s.tokenHash, presented)
}
