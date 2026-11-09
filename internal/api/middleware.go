package api

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Límites del bloqueador por IP tras fallos de autenticación.
const (
	maxFailures     = 5
	failureWindow   = time.Minute
	blockDuration   = 5 * time.Minute
	limiterSweepGap = 10 * time.Minute
)

// protected exige un token Bearer válido.
func (s *Server) protected(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)

		if s.limiter.blocked(ip) {
			w.Header().Set("Retry-After", "300")
			writeError(w, http.StatusTooManyRequests,
				"demasiados intentos fallidos desde esta IP; inténtalo de nuevo en unos minutos")
			return
		}

		token := BearerToken(r)
		if token == "" {
			s.limiter.recordFailure(ip)
			writeError(w, http.StatusUnauthorized, "falta el token de autenticación (Authorization: Bearer)")
			return
		}

		if err := s.verifyToken(token); err != nil {
			s.limiter.recordFailure(ip)
			writeError(w, http.StatusUnauthorized, "token inválido")
			return
		}

		s.limiter.recordSuccess(ip)
		next(w, r)
	}
}

// securityHeaders añade cabeceras defensivas a todas las respuestas.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}

		if s.corsOrigin != "" {
			origin := r.Header.Get("Origin")
			if origin == s.corsOrigin {
				h.Set("Access-Control-Allow-Origin", origin)
				h.Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
				h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
				h.Set("Vary", "Origin")
			}
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// clientIP devuelve la IP del cliente usando la conexión directa.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// failureRecord lleva la cuenta de fallos de una IP.
type failureRecord struct {
	count   int
	first   time.Time
	blocked bool
	until   time.Time
}

// failureLimiter bloquea IPs que fallan la autenticación repetidamente.
type failureLimiter struct {
	mu      sync.Mutex
	records map[string]*failureRecord
	swept   time.Time
}

// newFailureLimiter crea el limitador.
func newFailureLimiter() *failureLimiter {
	return &failureLimiter{records: map[string]*failureRecord{}, swept: time.Now()}
}

// blocked indica si la IP está bloqueada.
func (l *failureLimiter) blocked(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.sweepLocked()
	record, ok := l.records[ip]
	if !ok || !record.blocked {
		return false
	}
	if time.Now().After(record.until) {
		record.blocked = false
		record.count = 0
		return false
	}
	return true
}

// recordFailure suma un fallo y bloquea si supera el umbral.
func (l *failureLimiter) recordFailure(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.sweepLocked()
	record, ok := l.records[ip]
	if !ok {
		record = &failureRecord{first: time.Now()}
		l.records[ip] = record
	}

	if time.Since(record.first) > failureWindow {
		record.count = 0
		record.first = time.Now()
	}

	record.count++
	if record.count >= maxFailures {
		record.blocked = true
		record.until = time.Now().Add(blockDuration)
	}
}

// recordSuccess limpia el historial de fallos de la IP.
func (l *failureLimiter) recordSuccess(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.records, ip)
}

// sweepLocked elimina los registros antiguos para no crecer sin límite.
func (l *failureLimiter) sweepLocked() {
	now := time.Now()
	if now.Sub(l.swept) < limiterSweepGap {
		return
	}
	l.swept = now
	for ip, record := range l.records {
		if now.Sub(record.first) > failureWindow && !record.blocked {
			delete(l.records, ip)
		}
	}
}
