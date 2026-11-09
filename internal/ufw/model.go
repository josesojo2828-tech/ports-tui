// Package ufw es el adaptador hacia UFW (Uncomplicated Firewall).
//
// Habla con el binario `ufw` mediante su CLI, que es la interfaz estable y
// soportada del proyecto. Toda la salida se parsea desde el formato oficial
// de `ufw status numbered` y `ufw status verbose`.
package ufw

import (
	"fmt"
	"strconv"
	"strings"
)

// Acciones soportadas por UFW.
const (
	ActionAllow  = "ALLOW"
	ActionDeny   = "DENY"
	ActionReject = "REJECT"
	ActionLimit  = "LIMIT"
)

// Direcciones de tráfico.
const (
	DirectionIn  = "IN"
	DirectionOut = "OUT"
	DirectionFwd = "FWD"
)

// Status resume el estado global del firewall.
type Status struct {
	// Active indica si el firewall está habilitado.
	Active bool `json:"active"`
	// Logging es "on", "off" o "on (low)".
	Logging string `json:"logging"`
	// DefaultIncoming / DefaultOutgoing / DefaultRouted son las políticas.
	DefaultIncoming string `json:"default_incoming"`
	DefaultOutgoing string `json:"default_outgoing"`
	DefaultRouted   string `json:"default_routed"`
	// Raw conserva la salida original de ufw.
	Raw string `json:"raw,omitempty"`
}

// DefaultIncomingAllow indica si la política de entrada es permisiva.
func (s *Status) DefaultIncomingAllow() bool {
	return strings.EqualFold(s.DefaultIncoming, "allow")
}

// Target describe el destino de una regla.
type Target struct {
	// Address es "any", "Anywhere (v6)", una IP o un CIDR.
	Address string `json:"address"`
	// Port es "22", "22:80" o "any".
	Port string `json:"port"`
	// Proto es "tcp", "udp" o "any".
	Proto string `json:"proto"`
}

// PortRange devuelve el rango de puertos del target. Si el target cubre
// cualquier puerto devuelve 0, 65535.
func (t Target) PortRange() (low, high int) {
	if t.Port == "" || strings.EqualFold(t.Port, "any") {
		return 0, 65535
	}
	parts := strings.Split(t.Port, ":")
	low, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 65535
	}
	high = low
	if len(parts) > 1 {
		if v, err := strconv.Atoi(parts[1]); err == nil {
			high = v
		}
	}
	if high < low {
		low, high = high, low
	}
	return low, high
}

// Matches indica si el target cubre un puerto/protocolo concreto.
func (t Target) Matches(port int, proto string) bool {
	low, high := t.PortRange()
	if port < low || port > high {
		return false
	}
	if t.Proto == "" || strings.EqualFold(t.Proto, "any") {
		return true
	}
	return strings.EqualFold(t.Proto, proto)
}

// Rule es una regla de UFW ya parseada.
type Rule struct {
	// Number es el índice en la lista numerada de ufw.
	Number int `json:"number"`
	// Action es ALLOW, DENY, REJECT o LIMIT.
	Action string `json:"action"`
	// Direction es IN, OUT o FWD.
	Direction string `json:"direction"`
	// Target es el destino (dirección + puerto/protocolo).
	Target Target `json:"target"`
	// Source es el origen de la regla.
	Source string `json:"source"`
	// Comment es el comentario de la regla, si tiene.
	Comment string `json:"comment,omitempty"`
	// Enabled indica si la regla está activa.
	Enabled bool `json:"enabled"`
	// IPv6 marca las reglas de IPv6.
	IPv6 bool `json:"ipv6"`
	// Raw es la línea original.
	Raw string `json:"raw,omitempty"`
}

// IsAllow indica si la regla permite el tráfico.
func (r Rule) IsAllow() bool { return strings.EqualFold(r.Action, ActionAllow) }

// IsDeny indica si la regla bloquea el tráfico.
func (r Rule) IsDeny() bool {
	return strings.EqualFold(r.Action, ActionDeny) || strings.EqualFold(r.Action, ActionReject)
}

// IsAnySource indica si la regla aplica desde cualquier origen.
func (r Rule) IsAnySource() bool {
	src := strings.ToLower(strings.TrimSpace(r.Source))
	return src == "" || src == "anywhere" || src == "any" ||
		(strings.HasPrefix(src, "anywhere") && !strings.Contains(src, "/"))
}

// Spec describe una regla a crear.
type Spec struct {
	// Port es "22", "22:80" o "any".
	Port string `json:"port"`
	// Proto es "tcp", "udp" o "any".
	Proto string `json:"proto"`
	// From es el origen ("any" o un CIDR). Vacío = any.
	From string `json:"from"`
	// Action es allow, deny, reject o limit.
	Action string `json:"action"`
	// Comment es opcional.
	Comment string `json:"comment"`
}

// Validate comprueba que la especificación sea segura y ejecutable.
func (s Spec) Validate() error {
	if strings.TrimSpace(s.Port) == "" {
		return fmt.Errorf("el puerto es obligatorio")
	}
	if !strings.EqualFold(s.Port, "any") {
		parts := strings.Split(s.Port, ":")
		if len(parts) > 2 {
			return fmt.Errorf("rango de puertos inválido: %s", s.Port)
		}
		for _, p := range parts {
			v, err := strconv.Atoi(p)
			if err != nil || v < 1 || v > 65535 {
				return fmt.Errorf("puerto inválido: %s", s.Port)
			}
		}
	}
	switch strings.ToLower(s.Proto) {
	case "", "any", "tcp", "udp":
	default:
		return fmt.Errorf("protocolo inválido: %s", s.Proto)
	}
	switch strings.ToLower(s.Action) {
	case "allow":
	case "deny":
	case "reject":
	case "limit":
	default:
		return fmt.Errorf("acción inválida: %s", s.Action)
	}
	return nil
}

// Normalize devuelve la spec con valores por defecto y en formato canónico.
func (s Spec) Normalize() Spec {
	out := s
	out.Port = strings.TrimSpace(out.Port)
	out.Proto = strings.ToLower(strings.TrimSpace(out.Proto))
	out.Action = strings.ToLower(strings.TrimSpace(out.Action))
	out.From = strings.TrimSpace(out.From)
	out.Comment = strings.TrimSpace(out.Comment)
	if out.Proto == "" {
		out.Proto = "any"
	}
	if out.From == "" {
		out.From = "any"
	}
	return out
}

// Describe devuelve una descripción legible de la regla.
func (s Spec) Describe() string {
	proto := strings.ToUpper(s.Proto)
	if proto == "ANY" {
		proto = "tcp/udp"
	}
	src := s.From
	if src == "" {
		src = "anywhere"
	}
	comment := ""
	if s.Comment != "" {
		comment = " (" + s.Comment + ")"
	}
	return fmt.Sprintf("%s %s/%s desde %s%s", strings.ToUpper(s.Action), s.Port, proto, src, comment)
}
