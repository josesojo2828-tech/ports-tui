package ufw

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

// ErrNotInstalled indica que el binario ufw no está en el sistema.
var ErrNotInstalled = errors.New("ufw no está instalado en el sistema")

// ErrNotRoot indica que la operación requiere privilegios de root.
var ErrNotRoot = errors.New("la operación requiere privilegios de root")

// Runner permite ejecutar comandos; se abstrae para testear sin tocar el sistema.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (stdout, stderr string, err error)
}

// Backend es el contrato que consumen la API y la TUI.
type Backend interface {
	// Name identifica el backend ("ufw" o "demo").
	Name() string
	// Available verifica que el backend pueda usarse.
	Available(ctx context.Context) error
	// Status devuelve el estado global del firewall.
	Status(ctx context.Context) (*Status, error)
	// Rules devuelve las reglas numeradas.
	Rules(ctx context.Context) ([]Rule, error)
	// Add crea una regla nueva.
	Add(ctx context.Context, spec Spec) error
	// Delete elimina la regla por su número.
	Delete(ctx context.Context, number int) error
	// SetRuleEnabled habilita o deshabilita una regla concreta.
	SetRuleEnabled(ctx context.Context, number int, enabled bool) error
	// SetEnabled habilita o deshabilita el firewall completo.
	SetEnabled(ctx context.Context, enabled bool) error
	// Reload recarga las reglas.
	Reload(ctx context.Context) error
}

// Client habla con el binario ufw del sistema.
type Client struct {
	// Bin es la ruta del ejecutable (por defecto "ufw").
	Bin string
	// Runner ejecuta los comandos.
	Runner Runner

	mu sync.Mutex
}

// NewClient devuelve un cliente sobre el ufw del sistema.
func NewClient() *Client {
	return &Client{Bin: "ufw", Runner: ExecRunner{}}
}

// Name implementa Backend.
func (c *Client) Name() string { return "ufw" }

// Available implementa Backend.
func (c *Client) Available(ctx context.Context) error {
	if _, err := exec.LookPath(c.Bin); err != nil {
		return ErrNotInstalled
	}
	return nil
}

// Status implementa Backend.
func (c *Client) Status(ctx context.Context) (*Status, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	stdout, stderr, err := c.Runner.Run(ctx, c.Bin, "status", "verbose")
	if err != nil && stdout == "" {
		return nil, wrapErr(err, stderr)
	}
	return ParseStatus(stdout)
}

// Rules implementa Backend.
func (c *Client) Rules(ctx context.Context) ([]Rule, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	stdout, stderr, err := c.Runner.Run(ctx, c.Bin, "status", "numbered")
	if err != nil && stdout == "" {
		return nil, wrapErr(err, stderr)
	}
	return ParseRules(stdout)
}

// Add implementa Backend.
func (c *Client) Add(ctx context.Context, spec Spec) error {
	normalized := spec.Normalize()
	if err := normalized.Validate(); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return ErrNotRoot
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	args := buildAddArgs(normalized)
	stdout, stderr, err := c.Runner.Run(ctx, c.Bin, args...)
	if err != nil {
		return wrapErr(err, stderr)
	}
	if msg := strings.TrimSpace(stdout + " " + stderr); msg != "" {
		// ufw responde "Rule added" / "Skipping adding existing rule".
		if strings.Contains(strings.ToLower(msg), "skipped") ||
			strings.Contains(strings.ToLower(msg), "existing rule") {
			return fmt.Errorf("la regla ya existe")
		}
	}
	return nil
}

// buildAddArgs arma la línea de comandos de ufw para crear una regla.
func buildAddArgs(spec Spec) []string {
	args := []string{spec.Action}

	from := spec.From
	if from == "" {
		from = "any"
	}
	args = append(args, "from", from, "to", "any")

	if !strings.EqualFold(spec.Port, "any") {
		args = append(args, "port", spec.Port)
		if spec.Proto != "" && !strings.EqualFold(spec.Proto, "any") {
			args = append(args, "proto", spec.Proto)
		}
	}

	if spec.Comment != "" {
		args = append(args, "comment", spec.Comment)
	}

	return args
}

// Delete implementa Backend.
func (c *Client) Delete(ctx context.Context, number int) error {
	if number <= 0 {
		return fmt.Errorf("número de regla inválido: %d", number)
	}
	if os.Geteuid() != 0 {
		return ErrNotRoot
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	stdout, stderr, err := c.Runner.Run(ctx, c.Bin, "--force", "delete", strconv.Itoa(number))
	if err != nil {
		return wrapErr(err, stderr)
	}
	if strings.Contains(strings.ToLower(stdout+stderr), "could not delete") {
		return fmt.Errorf("no se pudo eliminar la regla %d", number)
	}
	return nil
}

// SetRuleEnabled implementa Backend.
func (c *Client) SetRuleEnabled(ctx context.Context, number int, enabled bool) error {
	if number <= 0 {
		return fmt.Errorf("número de regla inválido: %d", number)
	}
	if os.Geteuid() != 0 {
		return ErrNotRoot
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	verb := "disable"
	if enabled {
		verb = "enable"
	}
	_, stderr, err := c.Runner.Run(ctx, c.Bin, verb, strconv.Itoa(number))
	if err != nil {
		return wrapErr(err, stderr)
	}
	return nil
}

// SetEnabled implementa Backend.
func (c *Client) SetEnabled(ctx context.Context, enabled bool) error {
	if os.Geteuid() != 0 {
		return ErrNotRoot
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	verb := "disable"
	if enabled {
		verb = "enable"
	}
	_, stderr, err := c.Runner.Run(ctx, c.Bin, verb)
	if err != nil {
		return wrapErr(err, stderr)
	}
	return nil
}

// Reload implementa Backend.
func (c *Client) Reload(ctx context.Context) error {
	if os.Geteuid() != 0 {
		return ErrNotRoot
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	_, stderr, err := c.Runner.Run(ctx, c.Bin, "reload")
	if err != nil {
		return wrapErr(err, stderr)
	}
	return nil
}

// ExecRunner ejecuta comandos con os/exec.
type ExecRunner struct{}

// Run implementa Runner.
func (ExecRunner) Run(ctx context.Context, name string, args ...string) (string, string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

// wrapErr combina el error de exec con la salida de stderr de ufw.
func wrapErr(err error, stderr string) error {
	msg := strings.TrimSpace(stderr)
	if msg == "" {
		return err
	}
	return fmt.Errorf("%w: %s", err, msg)
}
