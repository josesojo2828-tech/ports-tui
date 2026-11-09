package firewall

import (
	"testing"

	"github.com/josesojo2828-tech/ports-tui/internal/netinfo"
	"github.com/josesojo2828-tech/ports-tui/internal/ufw"
)

// listener crea un socket de prueba.
func listener(port int, ip string, proto string) netinfo.Listener {
	bind := "specific"
	if ip == "0.0.0.0" || ip == "::" {
		bind = "all"
	}
	if ip == "127.0.0.1" || ip == "::1" {
		bind = "loopback"
	}
	return netinfo.Listener{
		Proto:   proto,
		Family:  netinfo.FamilyIPv4,
		LocalIP: ip,
		Port:    port,
		Bind:    bind,
		State:   "listen",
		Process: "test",
	}
}

func rule(number int, action, port, proto, source string) ufw.Rule {
	return ufw.Rule{
		Number:    number,
		Action:    action,
		Direction: ufw.DirectionIn,
		Target:    ufw.Target{Address: "Anywhere", Port: port, Proto: proto},
		Source:    source,
		Enabled:   true,
	}
}

func TestExposicionPermitido(t *testing.T) {
	listeners := []netinfo.Listener{listener(8080, "0.0.0.0", "tcp")}
	rules := []ufw.Rule{rule(1, ufw.ActionAllow, "8080", "tcp", "Anywhere")}

	status := &ufw.Status{Active: true, DefaultIncoming: "deny"}
	exposure := analyzeExposure(listeners, rules, status)

	if len(exposure) != 1 {
		t.Fatalf("se esperaba 1 elemento, se obtuvieron %d", len(exposure))
	}
	if exposure[0].State != StateExposed {
		t.Errorf("estado: se esperaba %s, se obtuvo %s", StateExposed, exposure[0].State)
	}
	if exposure[0].Severity != SeverityCritical {
		t.Errorf("severidad: se esperaba %s, se obtuvo %s", SeverityCritical, exposure[0].Severity)
	}
	if exposure[0].Listener.Port != 8080 {
		t.Errorf("puerto inesperado: %d", exposure[0].Listener.Port)
	}
}

func TestExposicionBloqueadoPorRegla(t *testing.T) {
	listeners := []netinfo.Listener{listener(3306, "0.0.0.0", "tcp")}
	rules := []ufw.Rule{rule(1, ufw.ActionDeny, "3306", "tcp", "Anywhere")}

	status := &ufw.Status{Active: true, DefaultIncoming: "deny"}
	exposure := analyzeExposure(listeners, rules, status)

	if exposure[0].State != StateBlocked {
		t.Errorf("estado: se esperaba %s, se obtuvo %s", StateBlocked, exposure[0].State)
	}
	if exposure[0].Severity != SeveritySafe {
		t.Errorf("severidad: se esperaba %s, se obtuvo %s", SeveritySafe, exposure[0].Severity)
	}
}

func TestExposicionCubiertaPorPoliticaPorDefecto(t *testing.T) {
	listeners := []netinfo.Listener{listener(9000, "0.0.0.0", "tcp")}

	status := &ufw.Status{Active: true, DefaultIncoming: "deny"}
	exposure := analyzeExposure(listeners, nil, status)
	if exposure[0].State != StateDefaultBlocked {
		t.Errorf("estado: se esperaba %s, se obtuvo %s", StateDefaultBlocked, exposure[0].State)
	}

	statusAllow := &ufw.Status{Active: true, DefaultIncoming: "allow"}
	exposure = analyzeExposure(listeners, nil, statusAllow)
	if exposure[0].State != StateDefaultAllowed {
		t.Errorf("estado: se esperaba %s, se obtuvo %s", StateDefaultAllowed, exposure[0].State)
	}
	if exposure[0].Severity != SeverityCritical {
		t.Errorf("severidad: se esperaba %s, se obtuvo %s", SeverityCritical, exposure[0].Severity)
	}
}

func TestExposicionSinFirewall(t *testing.T) {
	listeners := []netinfo.Listener{listener(22, "0.0.0.0", "tcp")}

	status := &ufw.Status{Active: false}
	exposure := analyzeExposure(listeners, nil, status)

	if exposure[0].State != StateNoFirewall {
		t.Errorf("estado: se esperaba %s, se obtuvo %s", StateNoFirewall, exposure[0].State)
	}
	if exposure[0].Severity != SeverityHigh {
		t.Errorf("severidad: se esperaba %s, se obtuvo %s", SeverityHigh, exposure[0].Severity)
	}
}

func TestExposicionLoopbackConFirewallInactivo(t *testing.T) {
	listeners := []netinfo.Listener{listener(5432, "127.0.0.1", "tcp")}

	status := &ufw.Status{Active: false}
	exposure := analyzeExposure(listeners, nil, status)

	if exposure[0].State != StateLocal {
		t.Errorf("estado: se esperaba %s, se obtuvo %s", StateLocal, exposure[0].State)
	}
}

func TestExposicionRestringidaPorOrigen(t *testing.T) {
	listeners := []netinfo.Listener{listener(22, "0.0.0.0", "tcp")}
	rules := []ufw.Rule{rule(1, ufw.ActionAllow, "22", "tcp", "192.168.1.0/24")}

	status := &ufw.Status{Active: true, DefaultIncoming: "deny"}
	exposure := analyzeExposure(listeners, rules, status)

	if exposure[0].State != StateRestricted {
		t.Errorf("estado: se esperaba %s, se obtuvo %s", StateRestricted, exposure[0].State)
	}
	if exposure[0].Severity != SeverityMedium {
		t.Errorf("severidad: se esperaba %s, se obtuvo %s", SeverityMedium, exposure[0].Severity)
	}
}

func TestExposicionSoloLoopbackBajaSeveridad(t *testing.T) {
	listeners := []netinfo.Listener{listener(8080, "127.0.0.1", "tcp")}
	rules := []ufw.Rule{rule(1, ufw.ActionAllow, "8080", "tcp", "Anywhere")}

	status := &ufw.Status{Active: true, DefaultIncoming: "deny"}
	exposure := analyzeExposure(listeners, rules, status)

	if exposure[0].Severity != SeverityLow {
		t.Errorf("severidad: se esperaba %s, se obtuvo %s", SeverityLow, exposure[0].Severity)
	}
}

func TestReglaDeshabilitadaNoAplica(t *testing.T) {
	listeners := []netinfo.Listener{listener(8080, "0.0.0.0", "tcp")}
	disabled := rule(1, ufw.ActionAllow, "8080", "tcp", "Anywhere")
	disabled.Enabled = false

	status := &ufw.Status{Active: true, DefaultIncoming: "deny"}
	exposure := analyzeExposure(listeners, []ufw.Rule{disabled}, status)

	if exposure[0].State != StateDefaultBlocked {
		t.Errorf("estado: se esperaba %s, se obtuvo %s", StateDefaultBlocked, exposure[0].State)
	}
}

func TestReglasHuerfanas(t *testing.T) {
	listeners := []netinfo.Listener{listener(8080, "0.0.0.0", "tcp")}
	rules := []ufw.Rule{
		rule(1, ufw.ActionAllow, "8080", "tcp", "Anywhere"),
		rule(2, ufw.ActionAllow, "9999", "tcp", "Anywhere"),
	}

	orphans := findOrphanRules(rules, listeners)
	if len(orphans) != 1 {
		t.Fatalf("se esperaba 1 regla huérfana, se obtuvieron %d", len(orphans))
	}
	if orphans[0].Rule.Number != 2 {
		t.Errorf("regla huérfana: se esperaba la #2, se obtuvo la #%d", orphans[0].Rule.Number)
	}
}

func TestResumen(t *testing.T) {
	snapshot := &Snapshot{
		Listeners: []netinfo.Listener{
			listener(22, "0.0.0.0", "tcp"),
			listener(5432, "127.0.0.1", "tcp"),
		},
		Rules: []ufw.Rule{
			rule(1, ufw.ActionAllow, "22", "tcp", "Anywhere"),
			rule(2, ufw.ActionDeny, "5432", "tcp", "Anywhere"),
		},
		UFW: &ufw.Status{Active: true, DefaultIncoming: "deny"},
	}
	snapshot.Exposure = analyzeExposure(snapshot.Listeners, snapshot.Rules, snapshot.UFW)
	summary := summarize(snapshot)

	if summary.TotalListeners != 2 {
		t.Errorf("total de escuchas: se esperaba 2, se obtuvo %d", summary.TotalListeners)
	}
	if summary.PublicListeners != 1 {
		t.Errorf("públicos: se esperaba 1, se obtuvo %d", summary.PublicListeners)
	}
	if summary.ExposedPorts != 1 {
		t.Errorf("expuestos: se esperaba 1, se obtuvo %d", summary.ExposedPorts)
	}
	if summary.BlockedPorts != 1 {
		t.Errorf("bloqueados: se esperaba 1, se obtuvo %d", summary.BlockedPorts)
	}
	if summary.AllowRules != 1 || summary.DenyRules != 1 {
		t.Errorf("conteo de reglas: se esperaba 1 allow y 1 deny, se obtuvo %d y %d",
			summary.AllowRules, summary.DenyRules)
	}
}
