package netinfo

import "testing"

func TestParseHexAddrIPv4(t *testing.T) {
	// 0100007F es 127.0.0.1 en little-endian; 1F90 es el puerto 8080.
	ip, port, err := parseHexAddr("0100007F:1F90", FamilyIPv4)
	if err != nil {
		t.Fatalf("parseHexAddr devolvió error: %v", err)
	}
	if ip != "127.0.0.1" {
		t.Errorf("IP: se esperaba 127.0.0.1, se obtuvo %s", ip)
	}
	if port != 8080 {
		t.Errorf("puerto: se esperaba 8080, se obtuvo %d", port)
	}
}

func TestParseHexAddrIPv4Cero(t *testing.T) {
	ip, port, err := parseHexAddr("00000000:0016", FamilyIPv4)
	if err != nil {
		t.Fatalf("parseHexAddr devolvió error: %v", err)
	}
	if ip != "0.0.0.0" {
		t.Errorf("IP: se esperaba 0.0.0.0, se obtuvo %s", ip)
	}
	if port != 22 {
		t.Errorf("puerto: se esperaba 22, se obtuvo %d", port)
	}
}

func TestParseHexAddrIPv6(t *testing.T) {
	// ::ffff:127.0.0.1 codificado por el kernel. Go normaliza las
	// direcciones IPv4-mapped a su forma IPv4, por eso el resultado.
	ip, port, err := parseHexAddr("0000000000000000FFFF00000100007F:0050", FamilyIPv6)
	if err != nil {
		t.Fatalf("parseHexAddr devolvió error: %v", err)
	}
	if ip != "127.0.0.1" {
		t.Errorf("IP: se esperaba 127.0.0.1, se obtuvo %s", ip)
	}
	if port != 80 {
		t.Errorf("puerto: se esperaba 80, se obtuvo %d", port)
	}
}

func TestParseHexAddrIPv6Loopback(t *testing.T) {
	ip, _, err := parseHexAddr("00000000000000000000000001000000:1F90", FamilyIPv6)
	if err != nil {
		t.Fatalf("parseHexAddr devolvió error: %v", err)
	}
	if ip != "::1" {
		t.Errorf("IP: se esperaba ::1, se obtuvo %s", ip)
	}
}

func TestParseHexAddrInvalido(t *testing.T) {
	if _, _, err := parseHexAddr("ZZZZ:1F90", FamilyIPv4); err == nil {
		t.Error("se esperaba error con una dirección inválida")
	}
	if _, _, err := parseHexAddr("0100007F", FamilyIPv4); err == nil {
		t.Error("se esperaba error con una dirección sin puerto")
	}
}

func TestClassifyBind(t *testing.T) {
	cases := map[string]string{
		"0.0.0.0":     "all",
		"127.0.0.1":   "loopback",
		"192.168.1.5": "specific",
		"::":          "all",
		"::1":         "loopback",
	}
	for ip, want := range cases {
		if got := classifyBind(ip); got != want {
			t.Errorf("classifyBind(%s): se esperaba %s, se obtuvo %s", ip, want, got)
		}
	}
}

func TestSocketInode(t *testing.T) {
	inode, ok := socketInode("socket:[24247219]")
	if !ok {
		t.Fatal("se esperaba reconocer el enlace de socket")
	}
	if inode != 24247219 {
		t.Errorf("inode: se esperaba 24247219, se obtuvo %d", inode)
	}

	if _, ok := socketInode("/tmp/archivo"); ok {
		t.Error("un enlace normal no es un socket")
	}
}

func TestListenersDelSistema(t *testing.T) {
	collector := NewCollector()
	listeners, err := collector.Listeners()
	if err != nil {
		t.Fatalf("Listeners devolvió error: %v", err)
	}

	for _, l := range listeners {
		if l.Port <= 0 || l.Port > 65535 {
			t.Errorf("puerto inválido en %+v", l)
		}
		if l.Proto != ProtoTCP && l.Proto != ProtoUDP {
			t.Errorf("protocolo inesperado: %s", l.Proto)
		}
		if l.Family != FamilyIPv4 && l.Family != FamilyIPv6 {
			t.Errorf("familia inesperada: %s", l.Family)
		}
	}
}
