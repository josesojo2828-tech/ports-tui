// Package firewall cruza los sockets que escuchan con las reglas de UFW para
// responder la pregunta clave: ¿qué puertos están realmente expuestos?
package firewall

import (
	"time"

	"github.com/josesojo2828-tech/ports-tui/internal/netinfo"
	"github.com/josesojo2828-tech/ports-tui/internal/ufw"
)

// Estados de exposición de un puerto.
const (
	// StateExposed: hay una regla ALLOW desde cualquier origen.
	StateExposed = "expuesto"
	// StateRestricted: hay una regla ALLOW solo desde una red concreta.
	StateRestricted = "restringido"
	// StateBlocked: una regla DENY/REJECT lo bloquea.
	StateBlocked = "bloqueado"
	// StateDefaultBlocked: lo cubre la política por defecto (deny).
	StateDefaultBlocked = "bloqueado_por_defecto"
	// StateDefaultAllowed: lo cubre la política por defecto (allow).
	StateDefaultAllowed = "permitido_por_defecto"
	// StateNoFirewall: UFW está inactivo.
	StateNoFirewall = "sin_firewall"
	// StateLocal: el socket solo escucha en loopback.
	StateLocal = "local"
)

// Niveles de severidad para ordenar la vista.
const (
	SeverityCritical = "critico"
	SeverityHigh     = "alto"
	SeverityMedium   = "medio"
	SeverityLow      = "bajo"
	SeveritySafe     = "seguro"
)

// Exposure describe el estado de un puerto que escucha.
type Exposure struct {
	// Listener es el socket analizado.
	Listener netinfo.Listener `json:"listener"`
	// State es el estado de exposición.
	State string `json:"state"`
	// Severity clasifica el riesgo.
	Severity string `json:"severity"`
	// Detail explica el estado en una frase.
	Detail string `json:"detail"`
	// Rules son los números de las reglas de UFW que aplican.
	Rules []int `json:"rules,omitempty"`
	// HasRule indica si existe una regla explícita para este puerto.
	HasRule bool `json:"has_rule"`
}

// OrphanRule es una regla que permite un puerto sin proceso escuchando.
type OrphanRule struct {
	Rule ufw.Rule `json:"rule"`
	// Reason explica por qué sobra.
	Reason string `json:"reason"`
}

// Summary agrega las métricas del snapshot.
type Summary struct {
	// TotalListeners es el número de sockets que escuchan.
	TotalListeners int `json:"total_listeners"`
	// PublicListeners son los que escuchan en todas las interfaces.
	PublicListeners int `json:"public_listeners"`
	// ExposedPorts son los puertos abiertos y accesibles.
	ExposedPorts int `json:"exposed_ports"`
	// BlockedPorts son los puertos bloqueados por ufw.
	BlockedPorts int `json:"blocked_ports"`
	// UnprotectedPorts son los puertos sin regla y con ufw inactivo.
	UnprotectedPorts int `json:"unprotected_ports"`
	// TotalRules es el número de reglas de UFW.
	TotalRules int `json:"total_rules"`
	// AllowRules y DenyRules cuentan cada tipo de regla.
	AllowRules int `json:"allow_rules"`
	DenyRules  int `json:"deny_rules"`
	// FirewallActive indica si UFW está habilitado.
	FirewallActive bool `json:"firewall_active"`
}

// Snapshot es la fotografía completa del estado de puertos y firewall.
type Snapshot struct {
	// Hostname de la máquina analizada.
	Hostname string `json:"hostname"`
	// GeneratedAt marca el momento del snapshot.
	GeneratedAt time.Time `json:"generated_at"`
	// Backend indica si los datos vienen de ufw real o del modo demo.
	Backend string `json:"backend"`
	// UFW es el estado global del firewall.
	UFW *ufw.Status `json:"ufw"`
	// Rules son todas las reglas de UFW.
	Rules []ufw.Rule `json:"rules"`
	// Listeners son los sockets que escuchan.
	Listeners []netinfo.Listener `json:"listeners"`
	// Exposure cruza listeners con reglas.
	Exposure []Exposure `json:"exposure"`
	// OrphanRules son reglas sin proceso escuchando.
	OrphanRules []OrphanRule `json:"orphan_rules"`
	// Summary son las métricas agregadas.
	Summary Summary `json:"summary"`
}

// SeverityRank ordena las severidades de mayor a menor riesgo.
func SeverityRank(severity string) int {
	switch severity {
	case SeverityCritical:
		return 0
	case SeverityHigh:
		return 1
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 3
	default:
		return 4
	}
}
