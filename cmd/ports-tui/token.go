package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/josesojo2828-tech/ports-tui/internal/auth"
	"github.com/josesojo2828-tech/ports-tui/internal/client"
	"github.com/josesojo2828-tech/ports-tui/internal/config"
	"github.com/josesojo2828-tech/ports-tui/internal/tui"
)

// version devuelve la versión de la aplicación.
func version() string {
	if config.Version != "" {
		return config.Version
	}
	return "dev"
}

// runToken gestiona el token de autenticación.
func runToken(args []string) {
	if len(args) == 0 {
		fmt.Println("uso: ports-tui token <generate|show|rotate> [flags]")
		os.Exit(2)
	}

	sub := args[0]
	fs := flag.NewFlagSet("token "+sub, flag.ExitOnError)
	output := fs.String("output", config.DefaultClientConfig().TokenFile, "archivo donde guardar el token del cliente")
	daemonHash := fs.String("daemon-hash", config.DefaultTokenHash, "archivo del daemon con el hash del token")
	withDaemon := fs.Bool("daemon", false, "también escribe el hash en el archivo del daemon (requiere root)")
	quiet := fs.Bool("quiet", false, "no muestra el token en pantalla")
	_ = fs.Parse(args[1:])

	switch sub {
	case "generate", "rotate":
		token, err := auth.GenerateToken()
		if err != nil {
			fmt.Fprintf(os.Stderr, "no se pudo generar el token: %v\n", err)
			os.Exit(1)
		}

		if err := auth.WritePlainToken(*output, token); err != nil {
			fmt.Fprintf(os.Stderr, "no se pudo guardar el token en %s: %v\n", *output, err)
			os.Exit(1)
		}

		if *withDaemon {
			if err := auth.WriteTokenHash(*daemonHash, token); err != nil {
				fmt.Fprintf(os.Stderr, "no se pudo guardar el hash en %s: %v\n", *daemonHash, err)
				os.Exit(1)
			}
		}

		fmt.Printf("token guardado en %s (permisos 0600)\n", *output)
		if *withDaemon {
			fmt.Printf("hash escrito en %s\n", *daemonHash)
		}
		if !*quiet {
			fmt.Printf("\n%s\n\n%s\n", token, "Cópialo: solo se muestra ahora.")
		}
		if !*withDaemon {
			fmt.Printf("Para habilitarlo en el daemon ejecuta:\n  sudo ports-tui token rotate --daemon\n")
		}

	case "show":
		token, err := auth.ReadPlainToken(*output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "no hay token en %s\nGenera uno con: ports-tui token generate\n", *output)
			os.Exit(1)
		}
		fmt.Println(token)

	default:
		fmt.Fprintf(os.Stderr, "subcomando desconocido: %q\n", sub)
		os.Exit(2)
	}
}

// runTLS prepara el certificado auto-firmado del daemon.
func runTLS(args []string) {
	if len(args) == 0 {
		args = []string{"ensure"}
	}

	fs := flag.NewFlagSet("tls "+args[0], flag.ExitOnError)
	certPath := fs.String("cert", config.DefaultTLSCert, "ruta del certificado")
	keyPath := fs.String("key", config.DefaultTLSKey, "ruta de la clave privada")
	force := fs.Bool("force", false, "regenera el certificado aunque ya exista")
	_ = fs.Parse(args[1:])

	if args[0] != "ensure" {
		fmt.Fprintf(os.Stderr, "subcomando desconocido: %q\n", args[0])
		os.Exit(2)
	}

	if *force {
		os.Remove(*certPath)
		os.Remove(*keyPath)
	}

	if err := auth.EnsureSelfSignedCert(*certPath, *keyPath, nil, certValidity); err != nil {
		fmt.Fprintf(os.Stderr, "no se pudo generar el certificado: %v\n", err)
		os.Exit(1)
	}

	fingerprint, err := auth.CertFingerprint(*certPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "no se pudo leer la huella del certificado: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("certificado: %s\n", *certPath)
	fmt.Printf("clave:       %s\n", *keyPath)
	fmt.Printf("huella:      %s\n", fingerprint)
}

// runTUI abre la interfaz de terminal, hablando con el daemon.
func runTUI(args []string) {
	fs := flag.NewFlagSet("tui", flag.ExitOnError)
	server := fs.String("server", "", "URL del daemon (por defecto https://127.0.0.1:9443)")
	tokenFile := fs.String("token-file", "", "archivo con el token del cliente")
	caCert := fs.String("ca-cert", "", "certificado con el que validar el TLS del daemon")
	insecure := fs.Bool("insecure", false, "no valida el certificado TLS (solo pruebas)")
	configPath := fs.String("config", config.ClientConfigPath(), "archivo de configuración del cliente")
	_ = fs.Parse(args)

	cfg, err := config.LoadClientConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "no se pudo leer la configuración: %v\n", err)
		os.Exit(1)
	}
	if *server != "" {
		cfg.Server = *server
	}
	if *tokenFile != "" {
		cfg.TokenFile = *tokenFile
	}
	if *caCert != "" {
		cfg.CACert = *caCert
	}
	if *insecure {
		cfg.Insecure = true
	}

	token, err := auth.ReadPlainToken(config.ExpandPath(cfg.TokenFile))
	if err != nil {
		fmt.Fprintf(os.Stderr, "no se encontró el token del cliente en %s\n\n", config.ExpandPath(cfg.TokenFile))
		fmt.Println("Genera uno con:")
		fmt.Printf("  ports-tui token generate\n")
		fmt.Println("Si el daemon ya corre, habilita el token en él con:")
		fmt.Printf("  sudo ports-tui token rotate --daemon\n")
		os.Exit(1)
	}

	apiClient, err := client.New(cfg.Server, token, config.ExpandPath(cfg.CACert), cfg.Insecure)
	if err != nil {
		fmt.Fprintf(os.Stderr, "no se pudo crear el cliente: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := apiClient.Health(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "no se pudo contactar con el daemon en %s\n\n%v\n\n", cfg.Server, err)
		fmt.Println("¿Está corriendo el daemon?")
		fmt.Println("  sudo systemctl start ports-tui")
		fmt.Println("O lánzalo en modo demo (sin root):")
		fmt.Println("  ports-tui serve -demo -addr 127.0.0.1:9443")
		os.Exit(1)
	}

	model := tui.NewModel(apiClient, cfg.Server)
	program := tea.NewProgram(model, tea.WithAltScreen())
	if _, err := program.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "error ejecutando la TUI: %v\n", err)
		os.Exit(1)
	}
}

// homeDir devuelve el home del usuario actual.
func homeDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return home
}

// userConfigDir es el directorio de configuración del usuario.
func userConfigDir() string {
	return filepath.Join(homeDir(), ".config", config.AppName)
}

// goVersion devuelve la versión de Go con la que se compiló.
func goVersion() string { return runtime.Version() }
