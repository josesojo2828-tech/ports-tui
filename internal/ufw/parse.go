package ufw

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	// ruleLineRe captura "[ 3] 22/tcp   ALLOW IN   Anywhere   # ssh".
	ruleLineRe = regexp.MustCompile(`^\[\s*(\d+)\]\s*(.*)$`)
	// actionRe localiza la acción y la dirección dentro de la línea.
	actionRe = regexp.MustCompile(`(?i)\b(ALLOW|DENY|REJECT|LIMIT)\s+(IN|OUT|FWD)\b`)
	// portRe reconoce "22", "22:80", "22/tcp", "22:80/udp".
	portRe = regexp.MustCompile(`^(\d+)(?::(\d+))?(?:/(tcp|udp|any))?$`)
)

// ParseRules parsea la salida de `ufw status numbered`.
func ParseRules(output string) ([]Rule, error) {
	var rules []Rule

	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		match := ruleLineRe.FindStringSubmatch(trimmed)
		if match == nil {
			continue
		}

		number := 0
		fmt.Sscanf(match[1], "%d", &number)
		rest := match[2]

		comment := ""
		if idx := strings.Index(rest, "#"); idx >= 0 {
			comment = strings.TrimSpace(rest[idx+1:])
			rest = rest[:idx]
		}

		actionMatch := actionRe.FindStringSubmatch(rest)
		if actionMatch == nil {
			// Línea sin acción (cabecera de tabla o separador).
			continue
		}

		idx := strings.Index(rest, actionMatch[0])
		toPart := strings.TrimSpace(rest[:idx])
		fromPart := strings.TrimSpace(rest[idx+len(actionMatch[0]):])

		action := strings.ToUpper(actionMatch[1])
		direction := strings.ToUpper(actionMatch[2])

		target, targetIPv6 := parseTarget(toPart)
		source, sourceIPv6 := parseAddress(fromPart)

		rules = append(rules, Rule{
			Number:    number,
			Action:    action,
			Direction: direction,
			Target:    target,
			Source:    source,
			Comment:   comment,
			Enabled:   !strings.Contains(strings.ToLower(trimmed), "disabled"),
			IPv6:      targetIPv6 || sourceIPv6,
			Raw:       trimmed,
		})
	}

	return rules, nil
}

// parseTarget extrae dirección y puerto de la columna "To".
func parseTarget(s string) (Target, bool) {
	target := Target{Address: "any", Port: "any", Proto: "any"}
	ipv6 := false

	for _, token := range strings.Fields(s) {
		if m := portRe.FindStringSubmatch(token); m != nil {
			low := m[1]
			if m[2] != "" {
				low = low + ":" + m[2]
			}
			target.Port = low
			if m[3] != "" {
				target.Proto = strings.ToLower(m[3])
			} else {
				target.Proto = "any"
			}
			continue
		}

		switch {
		case token == "Anywhere":
			target.Address = "Anywhere"
		case strings.HasPrefix(token, "(") && strings.Contains(token, "v6"):
			ipv6 = true
			if target.Address == "any" || target.Address == "Anywhere" {
				target.Address = "Anywhere (v6)"
			}
		default:
			target.Address = token
			if strings.Contains(token, ":") {
				ipv6 = true
			}
		}
	}

	return target, ipv6
}

// parseAddress extrae el origen de la columna "From".
func parseAddress(s string) (string, bool) {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return "any", false
	}

	if fields[0] == "Anywhere" {
		if len(fields) > 1 && strings.Contains(fields[1], "v6") {
			return "Anywhere (v6)", true
		}
		return "Anywhere", false
	}

	return strings.Join(fields, " "), strings.Contains(s, "v6")
}

// ParseStatus parsea la salida de `ufw status verbose`.
func ParseStatus(output string) (*Status, error) {
	status := &Status{Raw: output}

	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)

		switch {
		case strings.HasPrefix(lower, "status:"):
			value := strings.TrimSpace(trimmed[len("status:"):])
			status.Active = strings.HasPrefix(strings.ToLower(value), "active")
		case strings.HasPrefix(lower, "logging:"):
			status.Logging = strings.TrimSpace(trimmed[len("logging:"):])
		case strings.HasPrefix(lower, "default:"):
			parseDefaults(status, trimmed[len("default:"):])
		}
	}

	if status.DefaultIncoming == "" {
		status.DefaultIncoming = "deny"
	}
	if status.DefaultOutgoing == "" {
		status.DefaultOutgoing = "allow"
	}
	if status.DefaultRouted == "" {
		status.DefaultRouted = "disabled"
	}

	return status, nil
}

// parseDefaults extrae "deny (incoming), allow (outgoing), ...".
func parseDefaults(status *Status, raw string) {
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		lower := strings.ToLower(part)
		switch {
		case strings.Contains(lower, "incoming"):
			status.DefaultIncoming = policyValue(part)
		case strings.Contains(lower, "outgoing"):
			status.DefaultOutgoing = policyValue(part)
		case strings.Contains(lower, "routed"):
			status.DefaultRouted = policyValue(part)
		}
	}
}

// policyValue toma el valor de "deny (incoming)".
func policyValue(part string) string {
	idx := strings.Index(part, "(")
	if idx < 0 {
		return strings.TrimSpace(part)
	}
	return strings.TrimSpace(part[:idx])
}
