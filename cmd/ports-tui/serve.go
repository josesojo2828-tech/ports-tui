package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/josesojo2828-tech/ports-tui/internal/api"
	"github.com/josesojo2828-tech/ports-tui/internal/audit"
	"github.com/josesojo2828-tech/ports-tui/internal/auth"
	"github.com/josesojo2828-tech/ports-tui/internal/config"
	"github.com/josesojo2828-tech/ports-tui/internal/firewall"
	"github.com/josesojo2828-tech/ports-tui/internal/ufw"
	"github.com/josesojo2828-tech/ports-tui/internal/web"
)

// certValidity es la vigencia del certificado auto-firmado.
const certValidity = 3 * 365 * 24 * time.Hour

// runServe levanta el daemon: API REST + dashboard web sobre TLS.
func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", "", "dirección de escucha (por defecto 127.0.0.1:9443)")
	configPath := fs.String("config", config.DaemonConfigPath(), "archivo de configuración del daemon")
	tokenFile := fs.String("token-file", "", "archivo con el hash del token (por defecto /etc/ports-tui/token.hash)")
	certPath := fs.String("tls-cert", "", "certificado TLS (por defecto /etc/ports-tui/tls/cert.pem)")
	keyPath := fs.String("tls-key", "", "clave privada TLS (por defecto /etc/ports-tui/tls/key.pem)")
	auditPath := fs.String("audit-log", "", "archivo de auditoría (por defecto /var/log/ports-tui/audit.log)")
	corsOrigin := fs.String("cors-origin", "", "origen CORS permitido (vacío = deshabilitado)")
	demo := fs.Bool("demo", false, "usa un UFW simulado, sin tocar el firewall real")
	_ = fs.Parse(args)

	cfg, err := config.LoadDaemonConfig(*configPath)
	if err != nil {
		log.Fatalf("no se pudo leer la configuración: %v", err)
	}
	if *addr != "" {
		cfg.ListenAddr = *addr
	}
	if *tokenFile != "" {
		cfg.TokenHashFile = *tokenFile
	}
	if *certPath != "" {
		cfg.TLSCert = *certPath
	}
	if *keyPath != "" {
		cfg.TLSKey = *keyPath
	}
	if *auditPath != "" {
		cfg.AuditLog = *auditPath
	}
	if *corsOrigin != "" {
		cfg.CORSOrigin = *corsOrigin
	}
	if *demo {
		cfg.Demo = true
	}

	// Token: el daemon solo guarda su hash.
	tokenHash, err := auth.ReadTokenHash(cfg.TokenHashFile)
	if err != nil {
		log.Fatalf("no hay token configurado en %s\n"+
			"Genera uno con: sudo ports-tui token generate --daemon", cfg.TokenHashFile)
	}

	// Certificado TLS.
	if err := auth.EnsureSelfSignedCert(cfg.TLSCert, cfg.TLSKey, nil, certValidity); err != nil {
		log.Fatalf("no se pudo preparar el certificado TLS: %v", err)
	}
	fingerprint, _ := auth.CertFingerprint(cfg.TLSCert)

	// Backend de UFW.
	var backend ufw.Backend
	if cfg.Demo {
		backend = ufw.NewFake()
		log.Println("modo demo: las reglas se simulan en memoria, el firewall real no se toca")
	} else {
		backend = ufw.NewClient()
		if err := backend.Available(context.Background()); err != nil {
			log.Fatalf("%v\nInstálalo con: sudo apt install ufw", err)
		}
		if os.Geteuid() != 0 {
			log.Println("aviso: no eres root; las consultas funcionan pero las cambios en ufw fallarán")
		}
	}

	svc := firewall.NewService(backend)

	auditLogger, err := audit.NewLogger(cfg.AuditLog)
	if err != nil {
		log.Printf("aviso: no se pudo abrir el log de auditoría %s: %v", cfg.AuditLog, err)
	}
	defer auditLogger.Close()

	apiServer := api.NewServer(api.Options{
		Service:    svc,
		TokenHash:  tokenHash,
		Audit:      auditLogger,
		CORSOrigin: cfg.CORSOrigin,
		Version:    version(),
	})

	webServer := web.NewServer(cfg.ListenAddr, apiServer.Handler())

	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           webServer.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		log.Fatalf("no se pudo cargar el certificado TLS: %v", err)
	}
	server.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}

	fmt.Printf("🛡️  ports-tui %s — daemon escuchando en https://%s\n", version(), cfg.ListenAddr)
	fmt.Printf("    token: %s (hash en %s)\n", maskToken(tokenHash), cfg.TokenHashFile)
	fmt.Printf("    TLS:   %s\n", fingerprint)
	fmt.Printf("    API:   https://%s/api/v1/health\n", cfg.ListenAddr)
	fmt.Println("    Ctrl+C para detener.")

	errCh := make(chan error, 1)
	go func() {
		if err := server.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errCh:
		log.Fatalf("el servidor web falló: %v", err)
	case sig := <-sigCh:
		fmt.Printf("\nSeñal %v recibida, deteniendo...\n", sig)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Printf("aviso: cierre incompleto: %v", err)
	}
}

// maskToken oculta el hash del token en la salida.
func maskToken(hash string) string {
	if len(hash) <= 8 {
		return "********"
	}
	return hash[:6] + "…" + hash[len(hash)-4:]
}
