// Package netinfo descubre los sockets que escuchan en la máquina.
//
// Lee directamente /proc/net/{tcp,tcp6,udp,udp6}, que es la fuente más
// fiable y no requiere binarios externos. Cada socket se correlaciona con
// su proceso propietario mediante el inode del socket y /proc/<pid>/fd.
package netinfo

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// Estado del socket en la tabla de TCP (campo st de /proc/net/tcp).
const tcpStateListen = "0A"

// Proto identifica el transporte de un socket.
const (
	ProtoTCP = "tcp"
	ProtoUDP = "udp"
)

// Familia de direcciones.
const (
	FamilyIPv4 = "ipv4"
	FamilyIPv6 = "ipv6"
)

// Listener describe un socket que escucha (o está enlazado) en la máquina.
type Listener struct {
	// Proto es "tcp" o "udp".
	Proto string `json:"proto"`
	// Family es "ipv4" o "ipv6".
	Family string `json:"family"`
	// LocalIP es la dirección a la que está enlazado el socket.
	LocalIP string `json:"local_ip"`
	// Port es el puerto local.
	Port int `json:"port"`
	// Bind clasifica el alcance: "all", "loopback" o "specific".
	Bind string `json:"bind"`
	// State describe el estado del socket TCP ("listen") o "unconn" en UDP.
	State string `json:"state"`
	// UID es el dueño del socket.
	UID int `json:"uid"`
	// Inode identifica el socket en la tabla del kernel.
	Inode uint64 `json:"inode"`
	// PID y Process identifican el proceso dueño (0 si no es visible).
	PID     int    `json:"pid"`
	Process string `json:"process"`
	Cmdline string `json:"cmdline,omitempty"`
	// User es el nombre de usuario dueño del proceso, si se pudo resolver.
	User string `json:"user,omitempty"`
}

// IsPublic indica si el socket escucha en todas las interfaces.
func (l Listener) IsPublic() bool { return l.Bind == "all" }

// Addr devuelve la dirección legible del socket.
func (l Listener) Addr() string {
	return net.JoinHostPort(l.LocalIP, strconv.Itoa(l.Port))
}

// Collector lee las tablas de sockets del kernel.
type Collector struct {
	// ProcRoot permite apuntar a un /proc alternativo (útil en tests).
	ProcRoot string

	cacheMu  sync.Mutex
	cacheRef *processCache
}

// NewCollector devuelve un colector sobre el /proc real.
func NewCollector() *Collector { return &Collector{} }

// procPath construye una ruta dentro del ProcRoot configurado.
func (c *Collector) procPath(parts ...string) string {
	root := c.ProcRoot
	if root == "" {
		root = "/proc"
	}
	return filepath.Join(append([]string{root}, parts...)...)
}

// Listeners devuelve todos los sockets en escucha o enlazados.
//
// Los sockets TCP se filtran por estado LISTEN; en UDP todos los sockets
// enlazados se consideran activos porque pueden recibir datagramas.
func (c *Collector) Listeners() ([]Listener, error) {
	var out []Listener
	var firstErr error

	for _, spec := range []struct {
		file   string
		proto  string
		family string
	}{
		{"/net/tcp", ProtoTCP, FamilyIPv4},
		{"/net/tcp6", ProtoTCP, FamilyIPv6},
		{"/net/udp", ProtoUDP, FamilyIPv4},
		{"/net/udp6", ProtoUDP, FamilyIPv6},
	} {
		listeners, err := c.parseSocketTable(spec.file, spec.proto, spec.family)
		if err != nil {
			if firstErr == nil && !os.IsNotExist(err) {
				firstErr = err
			}
			continue
		}
		out = append(out, listeners...)
	}

	if len(out) == 0 && firstErr != nil {
		return nil, firstErr
	}

	c.attachProcesses(out)
	return out, nil
}

// parseSocketTable lee una tabla de sockets del kernel.
func (c *Collector) parseSocketTable(name, proto, family string) ([]Listener, error) {
	path := c.procPath(name)
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []Listener
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		// La primera línea es la cabecera.
		if !strings.HasSuffix(fields[0], ":") || fields[0] == "sl:" {
			continue
		}

		local := fields[1]
		state := fields[3]

		if proto == ProtoTCP && !strings.EqualFold(state, tcpStateListen) {
			continue
		}

		ip, port, err := parseHexAddr(local, family)
		if err != nil {
			continue
		}

		uid, _ := strconv.Atoi(fields[7])
		inode, _ := strconv.ParseUint(fields[9], 10, 64)

		out = append(out, Listener{
			Proto:   proto,
			Family:  family,
			LocalIP: ip,
			Port:    port,
			Bind:    classifyBind(ip),
			State:   socketState(proto, state),
			UID:     uid,
			Inode:   inode,
		})
	}
	return out, scanner.Err()
}

// socketState traduce el estado del kernel a un texto legible.
func socketState(proto, state string) string {
	if proto == ProtoUDP {
		return "unconn"
	}
	if strings.EqualFold(state, tcpStateListen) {
		return "listen"
	}
	return strings.ToLower(state)
}

// classifyBind determina si el socket está expuesto a todas las interfaces.
func classifyBind(ip string) string {
	parsed := net.ParseIP(ip)
	switch {
	case parsed == nil:
		return "specific"
	case parsed.IsUnspecified():
		return "all"
	case parsed.IsLoopback():
		return "loopback"
	default:
		return "specific"
	}
}

// parseHexAddr decodifica "HEXADDR:HEXPORT" del formato del kernel.
func parseHexAddr(s, family string) (string, int, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("dirección inválida: %s", s)
	}

	raw, err := hex.DecodeString(parts[0])
	if err != nil {
		return "", 0, err
	}

	var ip net.IP
	switch family {
	case FamilyIPv6:
		if len(raw) != 16 {
			return "", 0, fmt.Errorf("dirección IPv6 inválida: %s", s)
		}
		reversed := make([]byte, 16)
		for i := 0; i < 4; i++ {
			for j := 0; j < 4; j++ {
				reversed[i*4+j] = raw[i*4+3-j]
			}
		}
		ip = net.IP(reversed)
	default:
		if len(raw) != 4 {
			return "", 0, fmt.Errorf("dirección IPv4 inválida: %s", s)
		}
		ip = net.IPv4(raw[3], raw[2], raw[1], raw[0])
	}

	portRaw, err := strconv.ParseUint(parts[1], 16, 32)
	if err != nil {
		return "", 0, err
	}

	return ip.String(), int(portRaw), nil
}
