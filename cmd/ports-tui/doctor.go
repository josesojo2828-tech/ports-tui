package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/josesojo2828-tech/ports-tui/internal/auth"
	"github.com/josesojo2828-tech/ports-tui/internal/config"
	"github.com/josesojo2828-tech/ports-tui/internal/ufw"
)

// runDoctor diagnostica el entorno de ejecución.
func runDoctor(args []string) {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	configPath := fs.String("config", config.DaemonConfigPath(), "archivo de configuración del daemon")
	_ = fs.Parse(args)

	cfg, err := config.LoadDaemonConfig(*configPath)
	if err != nil {
		fmt.Printf("✖ configuración ilegible (%s): %v\n", *configPath, err)
	} else {
		fmt.Printf("✔ configuración: %s\n", *configPath)
		fmt.Printf("  dirección de escucha: %s\n", cfg.ListenAddr)
	}

	fmt.Printf("✔ versión: %s (%s)\n", version(), goVersion())

	if os.Geteuid() == 0 {
		fmt.Println("✔ Privilegios: root (puede modificar ufw)")
	} else {
		fmt.Println("⚠ Privilegios: usuario normal (solo lectura sobre ufw)")
	}

	if path, err := exec.LookPath("ufw"); err == nil {
		fmt.Printf("✔ ufw instalado en %s\n", path)
		if out, err := exec.Command("ufw", "status").Output(); err == nil {
			fmt.Printf("  %s\n", firstLine(string(out)))
		}
	} else {
		fmt.Println("⚠ ufw no está instalado (apt install ufw)")
	}

	if hash, err := auth.ReadTokenHash(cfg.TokenHashFile); err == nil {
		fmt.Printf("✔ token del daemon: %s… (hash)\n", maskToken(hash))
	} else {
		fmt.Printf("⚠ sin token del daemon en %s\n", cfg.TokenHashFile)
		fmt.Println("  sudo ports-tui token generate --daemon")
	}

	clientCfg, _ := config.LoadClientConfig(config.ClientConfigPath())
	if token, err := auth.ReadPlainToken(config.ExpandPath(clientCfg.TokenFile)); err == nil {
		fmt.Printf("✔ token del cliente: %s… (en %s)\n", maskToken(auth.HashToken(token)), config.ExpandPath(clientCfg.TokenFile))
	} else {
		fmt.Printf("⚠ sin token del cliente en %s\n", config.ExpandPath(clientCfg.TokenFile))
		fmt.Println("  ports-tui token generate")
	}

	if _, err := os.Stat(cfg.TLSCert); err == nil {
		fingerprint, _ := auth.CertFingerprint(cfg.TLSCert)
		fmt.Printf("✔ certificado TLS: %s\n  huella: %s\n", cfg.TLSCert, fingerprint)
	} else {
		fmt.Printf("⚠ sin certificado TLS en %s (se genera solo)\n", cfg.TLSCert)
	}

	if _, err := os.Stat(cfg.AuditLog); err == nil {
		fmt.Printf("✔ log de auditoría: %s\n", cfg.AuditLog)
	} else {
		fmt.Printf("⚠ sin log de auditoría en %s\n", cfg.AuditLog)
	}

	// Estado real del firewall.
	backend := ufw.NewClient()
	if err := backend.Available(context.Background()); err == nil {
		if status, err := backend.Status(context.Background()); err == nil {
			fmt.Printf("✔ firewall: %s (entrada por defecto: %s)\n",
				boolLabel(status.Active), status.DefaultIncoming)
		}
	}
}

// firstLine devuelve la primera línea no vacía de un texto.
func firstLine(text string) string {
	for _, line := range strings.Split(text, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

// boolLabel traduce un booleano a texto legible.
func boolLabel(value bool) string {
	if value {
		return "activo"
	}
	return "inactivo"
}
