// Command ports-tui gestiona los puertos de la máquina y su firewall UFW
// desde la terminal o desde el navegador, con una API local protegida por
// token Bearer y TLS.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		runTUI(os.Args[1:])
		return
	}

	switch os.Args[1] {
	case "serve":
		runServe(os.Args[2:])
	case "tui":
		runTUI(os.Args[2:])
	case "token":
		runToken(os.Args[2:])
	case "tls":
		runTLS(os.Args[2:])
	case "doctor":
		runDoctor(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Printf("ports-tui %s\n", version())
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "comando desconocido: %q\n\n", os.Args[1])
		printUsage()
		os.Exit(2)
	}
}

// printUsage muestra la ayuda de la CLI.
func printUsage() {
	fmt.Print(`ports-tui — control de puertos y firewall UFW

USO
  ports-tui [flags]              Abre la TUI (equivale a "ports-tui tui")
  ports-tui serve [flags]        Levanta el daemon (API + dashboard web)
  ports-tui token <sub> [flags]  Gestiona el token de autenticación
  ports-tui tls ensure [flags]   Genera el certificado TLS auto-firmado
  ports-tui doctor [flags]       Diagnostica el entorno
  ports-tui version              Muestra la versión

SUBCOMANDOS DE TOKEN
  generate   Crea un token nuevo y lo guarda para el cliente
  show       Muestra el token del cliente
  rotate     Genera un token nuevo invalidando el anterior

`)
}
