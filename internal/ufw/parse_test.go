package ufw

import (
	"context"
	"testing"
)

const sampleNumbered = `Status: active

     To                         Action      From
     --                         ------      ----
[ 1] 22/tcp                     ALLOW IN    Anywhere
[ 2] 80/tcp                     ALLOW IN    Anywhere                   # Apache
[ 3] 192.168.1.0/24 22/tcp      ALLOW IN    192.168.1.0/24
[ 4] Anywhere (v6)              ALLOW IN    Anywhere (v6)
[ 5] 3306/tcp                    DENY IN     Anywhere
[ 6] 1000:2000/udp               LIMIT IN    Anywhere
`

func TestParseRules(t *testing.T) {
	rules, err := ParseRules(sampleNumbered)
	if err != nil {
		t.Fatalf("ParseRules devolvió error: %v", err)
	}
	if len(rules) != 6 {
		t.Fatalf("se esperaban 6 reglas, se obtuvieron %d", len(rules))
	}

	first := rules[0]
	if first.Number != 1 {
		t.Errorf("número: se esperaba 1, se obtuvo %d", first.Number)
	}
	if first.Action != ActionAllow {
		t.Errorf("acción: se esperaba ALLOW, se obtuvo %s", first.Action)
	}
	if first.Direction != DirectionIn {
		t.Errorf("dirección: se esperaba IN, se obtuvo %s", first.Direction)
	}
	if first.Target.Port != "22" || first.Target.Proto != "tcp" {
		t.Errorf("destino: se esperaba 22/tcp, se obtuvo %s/%s", first.Target.Port, first.Target.Proto)
	}
	if first.Source != "Anywhere" {
		t.Errorf("origen: se esperaba Anywhere, se obtuvo %s", first.Source)
	}
	if !first.IsAnySource() {
		t.Error("la regla 1 debería aplicar desde cualquier origen")
	}

	if rules[1].Comment != "Apache" {
		t.Errorf("comentario: se esperaba Apache, se obtuvo %q", rules[1].Comment)
	}

	third := rules[2]
	if third.Target.Address != "192.168.1.0/24" {
		t.Errorf("dirección destino: se esperaba 192.168.1.0/24, se obtuvo %s", third.Target.Address)
	}
	if third.Target.Port != "22" || third.Target.Proto != "tcp" {
		t.Errorf("puerto: se esperaba 22/tcp, se obtuvo %s/%s", third.Target.Port, third.Target.Proto)
	}
	if third.Source != "192.168.1.0/24" {
		t.Errorf("origen: se esperaba 192.168.1.0/24, se obtuvo %s", third.Source)
	}
	if third.IsAnySource() {
		t.Error("la regla 3 no debe aplicar desde cualquier origen")
	}

	fourth := rules[3]
	if !fourth.IPv6 {
		t.Error("la regla 4 debería marcarse como IPv6")
	}
	if fourth.Target.Port != "any" {
		t.Errorf("la regla 4 cubre cualquier puerto, se obtuvo %s", fourth.Target.Port)
	}

	if rules[4].Action != ActionDeny {
		t.Errorf("acción: se esperaba DENY, se obtuvo %s", rules[4].Action)
	}
	if !rules[4].IsDeny() {
		t.Error("la regla 5 debería considerarse de bloqueo")
	}

	sixth := rules[5]
	if sixth.Target.Port != "1000:2000" || sixth.Target.Proto != "udp" {
		t.Errorf("rango: se esperaba 1000:2000/udp, se obtuvo %s/%s", sixth.Target.Port, sixth.Target.Proto)
	}
	if sixth.Action != ActionLimit {
		t.Errorf("acción: se esperaba LIMIT, se obtuvo %s", sixth.Action)
	}
}

func TestParseRulesIgnoraCabeceras(t *testing.T) {
	rules, err := ParseRules("Status: inactive\n")
	if err != nil {
		t.Fatalf("ParseRules devolvió error: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("se esperaban 0 reglas, se obtuvieron %d", len(rules))
	}
}

func TestParseStatus(t *testing.T) {
	raw := `Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip
`

	status, err := ParseStatus(raw)
	if err != nil {
		t.Fatalf("ParseStatus devolvió error: %v", err)
	}
	if !status.Active {
		t.Error("el firewall debería estar activo")
	}
	if status.DefaultIncoming != "deny" {
		t.Errorf("política de entrada: se esperaba deny, se obtuvo %s", status.DefaultIncoming)
	}
	if status.DefaultOutgoing != "allow" {
		t.Errorf("política de salida: se esperaba allow, se obtuvo %s", status.DefaultOutgoing)
	}
	if status.DefaultRouted != "disabled" {
		t.Errorf("política de enrutado: se esperaba disabled, se obtuvo %s", status.DefaultRouted)
	}
	if status.Logging != "on (low)" {
		t.Errorf("logging: se esperaba 'on (low)', se obtuvo %s", status.Logging)
	}
}

func TestParseStatusInactivo(t *testing.T) {
	status, err := ParseStatus("Status: inactive\nLogging: off\n")
	if err != nil {
		t.Fatalf("ParseStatus devolvió error: %v", err)
	}
	if status.Active {
		t.Error("el firewall no debería estar activo")
	}
}

func TestTargetMatches(t *testing.T) {
	target := Target{Port: "1000:2000", Proto: "tcp"}
	if !target.Matches(1500, "tcp") {
		t.Error("1500/tcp debería estar dentro del rango")
	}
	if target.Matches(1500, "udp") {
		t.Error("1500/udp no coincide con un target tcp")
	}
	if target.Matches(3000, "tcp") {
		t.Error("3000/tcp está fuera del rango")
	}

	anyPort := Target{Port: "any", Proto: "any"}
	if !anyPort.Matches(4444, "udp") {
		t.Error("un target 'any' debería coincidir con cualquier puerto")
	}
}

func TestSpecValidate(t *testing.T) {
	cases := []struct {
		name string
		spec Spec
		ok   bool
	}{
		{"puerto válido", Spec{Port: "22", Proto: "tcp", Action: "allow"}, true},
		{"rango válido", Spec{Port: "8000:8100", Action: "allow"}, true},
		{"puerto fuera de rango", Spec{Port: "70000", Action: "allow"}, false},
		{"puerto vacío", Spec{Action: "allow"}, false},
		{"protocolo inválido", Spec{Port: "22", Proto: "sctp", Action: "allow"}, false},
		{"acción inválida", Spec{Port: "22", Action: "drop"}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.spec.Validate()
			if tc.ok && err != nil {
				t.Errorf("se esperaba válido, se obtuvo error: %v", err)
			}
			if !tc.ok && err == nil {
				t.Error("se esperaba un error de validación")
			}
		})
	}
}

func TestBuildAddArgs(t *testing.T) {
	spec := Spec{Port: "22", Proto: "tcp", From: "any", Action: "allow", Comment: "ssh"}.Normalize()
	args := buildAddArgs(spec)

	want := []string{"allow", "from", "any", "to", "any", "port", "22", "proto", "tcp", "comment", "ssh"}
	if len(args) != len(want) {
		t.Fatalf("argumentos: se esperaban %d, se obtuvieron %d (%v)", len(want), len(args), args)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("argumento %d: se esperaba %s, se obtuvo %s", i, want[i], args[i])
		}
	}
}

func TestFakeBackend(t *testing.T) {
	fake := NewFake()

	rules, err := fake.Rules(context.Background())
	if err != nil {
		t.Fatalf("Rules devolvió error: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("se esperaban 2 reglas iniciales, se obtuvieron %d", len(rules))
	}

	if err := fake.Add(context.Background(), Spec{Port: "443", Proto: "tcp", Action: "allow"}); err != nil {
		t.Fatalf("Add devolvió error: %v", err)
	}

	rules, _ = fake.Rules(context.Background())
	if len(rules) != 3 {
		t.Fatalf("se esperaban 3 reglas, se obtuvieron %d", len(rules))
	}

	// La regla duplicada debe rechazarse.
	if err := fake.Add(context.Background(), Spec{Port: "443", Proto: "tcp", Action: "allow"}); err == nil {
		t.Error("se esperaba error al duplicar una regla")
	}

	if err := fake.Delete(context.Background(), rules[2].Number); err != nil {
		t.Fatalf("Delete devolvió error: %v", err)
	}
	rules, _ = fake.Rules(context.Background())
	if len(rules) != 2 {
		t.Fatalf("se esperaban 2 reglas tras borrar, se obtuvieron %d", len(rules))
	}
}
