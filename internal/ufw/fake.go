package ufw

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

// Fake es un backend de UFW simulado en memoria.
//
// Sirve para dos cosas: ejecutar la demo sin root y sin ufw instalado, y
// probar la API sin tocar el firewall real. Genera texto con el mismo formato
// que el binario real y lo reparsea con el mismo parser, de modo que el
// camino de código ejercitado es el mismo que en producción.
type Fake struct {
	mu     sync.Mutex
	active bool
	rules  []Rule
	next   int
}

// NewFake devuelve un backend simulado con reglas de ejemplo.
func NewFake() *Fake {
	f := &Fake{active: true, next: 1}
	f.rules = []Rule{
		{
			Number:    f.take(),
			Action:    ActionAllow,
			Direction: DirectionIn,
			Target:    Target{Address: "Anywhere", Port: "22", Proto: "tcp"},
			Source:    "Anywhere",
			Comment:   "OpenSSH",
			Enabled:   true,
		},
		{
			Number:    f.take(),
			Action:    ActionAllow,
			Direction: DirectionIn,
			Target:    Target{Address: "Anywhere", Port: "443", Proto: "tcp"},
			Source:    "Anywhere",
			Comment:   "HTTPS",
			Enabled:   true,
		},
	}
	return f
}

func (f *Fake) take() int {
	n := f.next
	f.next++
	return n
}

// Name implementa Backend.
func (f *Fake) Name() string { return "demo" }

// Available implementa Backend.
func (f *Fake) Available(ctx context.Context) error { return nil }

// Status implementa Backend.
func (f *Fake) Status(ctx context.Context) (*Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	state := "inactive"
	if f.active {
		state = "active"
	}
	raw := fmt.Sprintf("Status: %s\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), disabled (routed)\nNew profiles: skip\n", state)
	return ParseStatus(raw)
}

// Rules implementa Backend.
func (f *Fake) Rules(ctx context.Context) ([]Rule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return ParseRules(f.renderRulesLocked())
}

// renderRulesLocked genera la salida de `ufw status numbered`.
func (f *Fake) renderRulesLocked() string {
	var b strings.Builder
	b.WriteString("Status: ")
	if f.active {
		b.WriteString("active")
	} else {
		b.WriteString("inactive")
	}
	b.WriteString("\n\n")
	b.WriteString("     To                         Action      From\n")
	b.WriteString("     --                         ------      ----\n")

	for _, rule := range f.rules {
		to := formatTarget(rule.Target)
		action := rule.Action + " " + rule.Direction
		if !rule.Enabled {
			action += " (disabled)"
		}
		line := fmt.Sprintf("[%2d] %-30s %-13s %s", rule.Number, to, action, rule.Source)
		if rule.Comment != "" {
			line += "                   # " + rule.Comment
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

// formatTarget replica la columna "To" de ufw.
func formatTarget(target Target) string {
	if target.Port != "" && !strings.EqualFold(target.Port, "any") {
		port := target.Port
		if target.Proto != "" && !strings.EqualFold(target.Proto, "any") {
			port = port + "/" + target.Proto
		}
		if target.Address != "" && !strings.EqualFold(target.Address, "any") {
			return target.Address + " " + port
		}
		return port
	}
	if target.Address == "" {
		return "Anywhere"
	}
	return target.Address
}

// Add implementa Backend.
func (f *Fake) Add(ctx context.Context, spec Spec) error {
	normalized := spec.Normalize()
	if err := normalized.Validate(); err != nil {
		return err
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	action := ActionAllow
	switch normalized.Action {
	case "deny":
		action = ActionDeny
	case "reject":
		action = ActionReject
	case "limit":
		action = ActionLimit
	}

	proto := normalized.Proto
	if proto == "" {
		proto = "any"
	}
	source := normalized.From
	if source == "" {
		source = "Anywhere"
	}

	for _, existing := range f.rules {
		if existing.Target.Port == normalized.Port &&
			existing.Target.Proto == proto &&
			strings.EqualFold(existing.Source, source) &&
			existing.Action == action {
			return fmt.Errorf("la regla ya existe")
		}
	}

	f.rules = append(f.rules, Rule{
		Number:    f.take(),
		Action:    action,
		Direction: DirectionIn,
		Target:    Target{Address: "Anywhere", Port: normalized.Port, Proto: proto},
		Source:    source,
		Comment:   normalized.Comment,
		Enabled:   true,
	})
	return nil
}

// Delete implementa Backend.
func (f *Fake) Delete(ctx context.Context, number int) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	for i, rule := range f.rules {
		if rule.Number == number {
			f.rules = append(f.rules[:i], f.rules[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("no se encontró la regla %d", number)
}

// SetRuleEnabled implementa Backend.
func (f *Fake) SetRuleEnabled(ctx context.Context, number int, enabled bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	for i := range f.rules {
		if f.rules[i].Number == number {
			f.rules[i].Enabled = enabled
			return nil
		}
	}
	return fmt.Errorf("no se encontró la regla %d", number)
}

// SetEnabled implementa Backend.
func (f *Fake) SetEnabled(ctx context.Context, enabled bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.active = enabled
	return nil
}

// Reload implementa Backend.
func (f *Fake) Reload(ctx context.Context) error { return nil }
