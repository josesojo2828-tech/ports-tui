package firewall

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/josesojo2828-tech/ports-tui/internal/netinfo"
	"github.com/josesojo2828-tech/ports-tui/internal/ufw"
)

// nowFn permite fijar el reloj en tests.
var nowFn = time.Now

// Service combina el backend de UFW con el colector de sockets.
type Service struct {
	backend   ufw.Backend
	collector *netinfo.Collector
	hostname  string
}

// NewService construye el servicio de análisis.
func NewService(backend ufw.Backend) *Service {
	host, err := os.Hostname()
	if err != nil {
		host = "localhost"
	}
	return &Service{
		backend:   backend,
		collector: netinfo.NewCollector(),
		hostname:  host,
	}
}

// Backend devuelve el backend de UFW en uso.
func (s *Service) Backend() ufw.Backend { return s.backend }

// Snapshot construye el estado completo: reglas, sockets y exposición.
func (s *Service) Snapshot(ctx context.Context) (*Snapshot, error) {
	status, err := s.backend.Status(ctx)
	if err != nil {
		return nil, fmt.Errorf("no se pudo leer el estado de ufw: %w", err)
	}

	rules, err := s.backend.Rules(ctx)
	if err != nil {
		return nil, fmt.Errorf("no se pudieron leer las reglas de ufw: %w", err)
	}

	listeners, err := s.collector.Listeners()
	if err != nil {
		return nil, fmt.Errorf("no se pudieron leer los sockets: %w", err)
	}

	snapshot := &Snapshot{
		Hostname:    s.hostname,
		GeneratedAt: nowFn(),
		Backend:     s.backend.Name(),
		UFW:         status,
		Rules:       rules,
		Listeners:   listeners,
	}

	snapshot.Exposure = analyzeExposure(listeners, rules, status)
	snapshot.OrphanRules = findOrphanRules(rules, listeners)
	snapshot.Summary = summarize(snapshot)
	return snapshot, nil
}

// analyzeExposure cruza cada socket con las reglas aplicables.
func analyzeExposure(listeners []netinfo.Listener, rules []ufw.Rule, status *ufw.Status) []Exposure {
	exposure := make([]Exposure, 0, len(listeners))

	for _, listener := range listeners {
		item := Exposure{Listener: listener}

		applicable := applicableRules(listener, rules)

		if status == nil || !status.Active {
			item.State = StateNoFirewall
			item.Severity = SeverityHigh
			if listener.IsPublic() {
				item.Detail = "UFW está inactivo: el puerto queda accesible desde la red"
			} else {
				item.State = StateLocal
				item.Severity = SeverityLow
				item.Detail = "UFW está inactivo, pero el socket solo escucha en loopback"
			}
			exposure = append(exposure, item)
			continue
		}

		var allowAny, allowRestricted, deny []ufw.Rule
		for _, rule := range applicable {
			switch {
			case rule.IsAllow() && rule.IsAnySource():
				allowAny = append(allowAny, rule)
			case rule.IsAllow():
				allowRestricted = append(allowRestricted, rule)
			case rule.IsDeny():
				deny = append(deny, rule)
			}
		}

		for _, rule := range applicable {
			item.Rules = append(item.Rules, rule.Number)
		}
		item.HasRule = len(applicable) > 0

		switch {
		case len(allowAny) > 0:
			item.State = StateExposed
			item.Severity = SeverityCritical
			item.Detail = fmt.Sprintf("Regla %s lo permite desde cualquier origen", ruleList(allowAny))
			if !listener.IsPublic() {
				item.Severity = SeverityLow
				item.Detail = "Permitido por ufw, pero el socket solo escucha en loopback"
			}
		case len(allowRestricted) > 0:
			item.State = StateRestricted
			item.Severity = SeverityMedium
			item.Detail = fmt.Sprintf("Permitido solo desde %s (regla %s)",
				allowRestricted[0].Source, ruleList(allowRestricted))
			if !listener.IsPublic() {
				item.Severity = SeverityLow
			}
		case len(deny) > 0:
			item.State = StateBlocked
			item.Severity = SeveritySafe
			item.Detail = fmt.Sprintf("Bloqueado explícitamente (regla %s)", ruleList(deny))
		case status.DefaultIncomingAllow():
			item.State = StateDefaultAllowed
			item.Severity = SeverityCritical
			item.Detail = "Sin regla propia y política por defecto 'allow': queda abierto"
			if !listener.IsPublic() {
				item.Severity = SeverityLow
				item.Detail = "Política por defecto 'allow', pero el socket solo escucha en loopback"
			}
		default:
			item.State = StateDefaultBlocked
			item.Severity = SeveritySafe
			item.Detail = "Cubierto por la política por defecto 'deny'"
			if !listener.IsPublic() {
				item.Severity = SeverityLow
			}
		}

		exposure = append(exposure, item)
	}

	return exposure
}

// applicableRules devuelve las reglas que aplican a un socket.
func applicableRules(listener netinfo.Listener, rules []ufw.Rule) []ufw.Rule {
	var out []ufw.Rule
	for _, rule := range rules {
		if rule.Direction != "" && !strings.EqualFold(rule.Direction, ufw.DirectionIn) {
			continue
		}
		if !rule.Enabled {
			continue
		}
		if !rule.Target.Matches(listener.Port, listener.Proto) {
			continue
		}
		out = append(out, rule)
	}
	return out
}

// findOrphanRules detecta reglas ALLOW sin proceso escuchando.
func findOrphanRules(rules []ufw.Rule, listeners []netinfo.Listener) []OrphanRule {
	var orphans []OrphanRule

	for _, rule := range rules {
		if !rule.IsAllow() || !rule.Enabled {
			continue
		}
		if rule.Direction != "" && !strings.EqualFold(rule.Direction, ufw.DirectionIn) {
			continue
		}

		low, high := rule.Target.PortRange()
		if low == 0 && high == 65535 {
			// Regla que abre cualquier puerto: no se puede marcar como huérfana.
			continue
		}

		matched := false
		for _, listener := range listeners {
			if listener.Port >= low && listener.Port <= high && rule.Target.Matches(listener.Port, listener.Proto) {
				matched = true
				break
			}
		}
		if !matched {
			orphans = append(orphans, OrphanRule{
				Rule:   rule,
				Reason: fmt.Sprintf("ningún proceso escucha en %s", rule.Target.Port),
			})
		}
	}

	return orphans
}

// summarize calcula las métricas agregadas del snapshot.
func summarize(snapshot *Snapshot) Summary {
	summary := Summary{
		TotalListeners: len(snapshot.Listeners),
		TotalRules:     len(snapshot.Rules),
	}

	for _, rule := range snapshot.Rules {
		if rule.IsAllow() {
			summary.AllowRules++
		} else if rule.IsDeny() {
			summary.DenyRules++
		}
	}

	if snapshot.UFW != nil {
		summary.FirewallActive = snapshot.UFW.Active
	}

	for _, item := range snapshot.Exposure {
		if item.Listener.IsPublic() {
			summary.PublicListeners++
		}
		switch item.State {
		case StateExposed, StateDefaultAllowed:
			summary.ExposedPorts++
		case StateBlocked, StateDefaultBlocked:
			summary.BlockedPorts++
		case StateNoFirewall:
			summary.UnprotectedPorts++
		}
	}

	return summary
}

// ruleList formatea una lista de números de regla.
func ruleList(rules []ufw.Rule) string {
	if len(rules) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(rules))
	for _, rule := range rules {
		parts = append(parts, fmt.Sprintf("#%d", rule.Number))
	}
	return strings.Join(parts, ", ")
}
