// Package web sirve el dashboard HTML embebido y monta la API REST.
package web

import (
	"context"
	"embed"
	"io/fs"
	"net/http"
	"time"
)

//go:embed static/*
var staticFS embed.FS

// Server publica el dashboard web junto con la API.
type Server struct {
	httpServer *http.Server
	handler    http.Handler
	addr       string
}

// NewServer crea el servidor web.
//
// El dashboard se sirve en la misma raíz que la API, así que no hace falta
// CORS: el token viaja en la cabecera Authorization desde el mismo origen.
func NewServer(addr string, apiHandler http.Handler) *Server {
	mux := http.NewServeMux()

	sub, err := fs.Sub(staticFS, "static")
	if err == nil {
		mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(sub))))
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" && r.URL.Path != "/index.html" {
				http.NotFound(w, r)
				return
			}
			serveIndex(w, r, sub)
		})
	}

	if apiHandler != nil {
		mux.Handle("/api/", apiHandler)
	}

	handler := withSecurityHeaders(mux)

	return &Server{
		addr:    addr,
		handler: handler,
		httpServer: &http.Server{
			Addr:              addr,
			Handler:           handler,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       60 * time.Second,
		},
	}
}

// Handler devuelve el handler del dashboard con la API montada.
func (s *Server) Handler() http.Handler { return s.handler }

// Start comienza a escuchar.
func (s *Server) Start() error { return s.httpServer.ListenAndServe() }

// Shutdown detiene el servidor de forma ordenada.
func (s *Server) Shutdown(ctx context.Context) error { return s.httpServer.Shutdown(ctx) }

// Addr devuelve la dirección de escucha.
func (s *Server) Addr() string { return s.addr }

// serveIndex entrega el dashboard principal.
func serveIndex(w http.ResponseWriter, r *http.Request, sub fs.FS) {
	data, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// withSecurityHeaders aplica cabeceras defensivas al dashboard.
func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; "+
			"script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; "+
			"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "+
			"font-src 'self' https://fonts.gstatic.com; "+
			"img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}
