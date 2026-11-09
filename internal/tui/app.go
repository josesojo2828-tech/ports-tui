package tui

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/josesojo2828-tech/ports-tui/internal/client"
	"github.com/josesojo2828-tech/ports-tui/internal/firewall"
	"github.com/josesojo2828-tech/ports-tui/internal/ufw"
)

// Pestañas de la interfaz.
type activeTab int

const (
	tabPorts activeTab = iota
	tabRules
	tabStatus
)

// Mensajes internos del Bubble Tea.
type tickMsg time.Time

type snapshotMsg struct {
	snapshot *firewall.Snapshot
	err      error
}

type actionResultMsg struct {
	message string
	err     error
}

// Model es el estado de la TUI.
type Model struct {
	client    *client.Client
	daemon    string
	dashboard string

	currentTab activeTab
	snapshot   *firewall.Snapshot

	portsTable table.Model
	rulesTable table.Model

	onlyRisky bool

	width     int
	height    int
	statusMsg string
	isError   bool
	loading   bool

	form *formModel
	// pendingConfirm guarda la acción a confirmar tras pulsar "x".
	pendingConfirm string
}

// NewModel crea el modelo inicial de la TUI.
func NewModel(apiClient *client.Client, daemon string) Model {
	portCols := []table.Column{
		{Title: "PUERTO", Width: 8},
		{Title: "PROTO", Width: 6},
		{Title: "DIRECCIÓN", Width: 24},
		{Title: "PROCESO", Width: 18},
		{Title: "PID", Width: 7},
		{Title: "ESTADO", Width: 18},
		{Title: "REGLAS", Width: 10},
	}
	ports := table.New(
		table.WithColumns(portCols),
		table.WithFocused(true),
		table.WithHeight(10),
	)

	ruleCols := []table.Column{
		{Title: "#", Width: 4},
		{Title: "ACCIÓN", Width: 9},
		{Title: "DESTINO", Width: 24},
		{Title: "ORIGEN", Width: 20},
		{Title: "COMENTARIO", Width: 24},
		{Title: "ESTADO", Width: 12},
	}
	rules := table.New(
		table.WithColumns(ruleCols),
		table.WithFocused(false),
		table.WithHeight(10),
	)

	style := table.DefaultStyles()
	style.Header = style.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("#334155")).
		BorderBottom(true).
		Bold(true).
		Foreground(lipgloss.Color("#93c5fd"))
	style.Selected = style.Selected.
		Foreground(lipgloss.Color("#ffffff")).
		Background(lipgloss.Color("#1d4ed8")).
		Bold(true)
	ports.SetStyles(style)
	rules.SetStyles(style)

	return Model{
		client:     apiClient,
		daemon:     daemon,
		portsTable: ports,
		rulesTable: rules,
		loading:    true,
	}
}

// Init dispara la carga inicial y el refresco periódico.
func (m Model) Init() tea.Cmd {
	return tea.Batch(m.fetchCmd(), m.tickCmd())
}

func (m Model) tickCmd() tea.Cmd {
	return tea.Tick(4*time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

// fetchCmd descarga el snapshot del daemon.
func (m Model) fetchCmd() tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		snapshot, err := m.client.Snapshot(ctx)
		if err != nil {
			return snapshotMsg{err: err}
		}
		return snapshotMsg{snapshot: snapshot}
	}
}

// Update maneja mensajes y pulsaciones.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	// El formulario modal captura todas las teclas mientras está abierto.
	if m.form != nil {
		return m.form.update(msg)
	}

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		height := msg.Height - 13
		if height < 5 {
			height = 5
		}
		m.portsTable.SetHeight(height)
		m.rulesTable.SetHeight(height)

	case tickMsg:
		cmds = append(cmds, m.fetchCmd(), m.tickCmd())

	case snapshotMsg:
		m.loading = false
		if msg.err != nil {
			m.statusMsg = fmt.Sprintf("No se pudo leer el estado: %v", msg.err)
			m.isError = true
			return m, nil
		}
		m.snapshot = msg.snapshot
		m.refreshTables()

	case actionResultMsg:
		m.loading = false
		m.statusMsg = msg.message
		m.isError = msg.err != nil
		cmds = append(cmds, m.fetchCmd())

	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit

		case "tab":
			m.currentTab = (m.currentTab + 1) % 3
			m.updateTableFocus()

		case "shift+tab":
			m.currentTab = (m.currentTab + 2) % 3
			m.updateTableFocus()

		case "1":
			m.currentTab = tabPorts
			m.updateTableFocus()
		case "2":
			m.currentTab = tabRules
			m.updateTableFocus()
		case "3":
			m.currentTab = tabStatus
			m.updateTableFocus()

		case "R":
			m.loading = true
			m.statusMsg = "Actualizando..."
			m.isError = false
			cmds = append(cmds, m.fetchCmd())

		case "f":
			m.onlyRisky = !m.onlyRisky
			m.refreshTables()
			if m.onlyRisky {
				m.statusMsg = "Filtro: solo puertos con riesgo"
			} else {
				m.statusMsg = "Filtro: todos los puertos"
			}
			m.isError = false

		case "o":
			m.form = newFormModel("Abrir puerto", "allow")
			return m, nil

		case "c":
			if port, ok := m.selectedPort(); ok {
				m.form = newFormModel("Cerrar puerto", "deny")
				m.form.setPort(strconv.Itoa(port))
				return m, nil
			}
			m.statusMsg = "Selecciona un puerto en la pestaña de escuchas"
			m.isError = true

		case "x":
			m.handleDeleteKey()

		case "e":
			if m.currentTab == tabRules {
				if number, ok := m.selectedRuleNumber(); ok {
					m.statusMsg = fmt.Sprintf("Habilitando la regla #%d...", number)
					m.isError = false
					cmds = append(cmds, m.toggleRuleCmd(number, true))
				}
			}

		case "D":
			if m.currentTab == tabRules {
				if number, ok := m.selectedRuleNumber(); ok {
					m.statusMsg = fmt.Sprintf("Deshabilitando la regla #%d...", number)
					m.isError = false
					cmds = append(cmds, m.toggleRuleCmd(number, false))
				}
			}

		case "y":
			if m.pendingConfirm != "" {
				confirm := m.pendingConfirm
				m.pendingConfirm = ""
				m.statusMsg = confirm + "..."
				m.isError = false
				cmds = append(cmds, m.deleteRuleCmd(confirmNumber(confirm)))
			}

		case "n":
			if m.pendingConfirm != "" {
				m.pendingConfirm = ""
				m.statusMsg = "Operación cancelada"
				m.isError = false
			}
		}
	}

	// Las teclas de navegación se delegan a la tabla activa.
	var cmd tea.Cmd
	switch m.currentTab {
	case tabPorts:
		m.portsTable, cmd = m.portsTable.Update(msg)
	case tabRules:
		m.rulesTable, cmd = m.rulesTable.Update(msg)
	}
	cmds = append(cmds, cmd)

	return m, tea.Batch(cmds...)
}

// handleDeleteKey pide confirmación antes de borrar una regla.
func (m *Model) handleDeleteKey() {
	if m.currentTab != tabRules {
		m.statusMsg = "Cambia a la pestaña de reglas para eliminar"
		m.isError = true
		return
	}
	number, ok := m.selectedRuleNumber()
	if !ok {
		m.statusMsg = "No hay ninguna regla seleccionada"
		m.isError = true
		return
	}
	m.pendingConfirm = fmt.Sprintf("regla #%d", number)
	m.statusMsg = fmt.Sprintf("¿Eliminar la regla #%d? (s = sí, n = no)", number)
	m.isError = false
}

// refreshTables reconstruye las filas con el último snapshot.
func (m *Model) refreshTables() {
	if m.snapshot == nil {
		return
	}

	exposure := make([]firewall.Exposure, 0, len(m.snapshot.Exposure))
	for _, item := range m.snapshot.Exposure {
		if m.onlyRisky && item.Severity == firewall.SeveritySafe {
			continue
		}
		exposure = append(exposure, item)
	}
	sort.SliceStable(exposure, func(i, j int) bool {
		ri := firewall.SeverityRank(exposure[i].Severity)
		rj := firewall.SeverityRank(exposure[j].Severity)
		if ri != rj {
			return ri < rj
		}
		return exposure[i].Listener.Port < exposure[j].Listener.Port
	})

	var portRows []table.Row
	for _, item := range exposure {
		listener := item.Listener
		process := listener.Process
		if process == "" {
			process = "-"
		}
		rules := "-"
		if len(item.Rules) > 0 {
			parts := make([]string, 0, len(item.Rules))
			for _, n := range item.Rules {
				parts = append(parts, "#"+strconv.Itoa(n))
			}
			rules = strings.Join(parts, " ")
		}
		portRows = append(portRows, table.Row{
			strconv.Itoa(listener.Port),
			strings.ToUpper(listener.Proto),
			listener.Addr(),
			process,
			pidLabel(listener.PID),
			stateIcon(item.State) + " " + item.State,
			rules,
		})
	}
	m.portsTable.SetRows(portRows)

	var ruleRows []table.Row
	for _, rule := range m.snapshot.Rules {
		state := "activa"
		if !rule.Enabled {
			state = "deshabilitada"
		}
		ruleRows = append(ruleRows, table.Row{
			strconv.Itoa(rule.Number),
			rule.Action,
			formatRuleTarget(rule),
			rule.Source,
			rule.Comment,
			state,
		})
	}
	m.rulesTable.SetRows(ruleRows)
}

// formatRuleTarget arma la columna de destino de una regla.
func formatRuleTarget(rule ufw.Rule) string {
	port := rule.Target.Port
	if port == "" {
		port = "any"
	}
	proto := rule.Target.Proto
	if proto != "" && !strings.EqualFold(proto, "any") {
		port = port + "/" + proto
	}
	if rule.Target.Address != "" && !strings.EqualFold(rule.Target.Address, "any") &&
		!strings.EqualFold(rule.Target.Address, "Anywhere") {
		return rule.Target.Address + " " + port
	}
	return port
}

// pidLabel formatea el PID.
func pidLabel(pid int) string {
	if pid <= 0 {
		return "-"
	}
	return strconv.Itoa(pid)
}

// selectedPort devuelve el puerto seleccionado en la tabla de escuchas.
func (m Model) selectedPort() (int, bool) {
	if m.snapshot == nil {
		return 0, false
	}
	cursor := m.portsTable.Cursor()
	items := m.visibleExposure()
	if cursor < 0 || cursor >= len(items) {
		return 0, false
	}
	return items[cursor].Listener.Port, true
}

// visibleExposure devuelve la lista ordenada y filtrada que se muestra.
func (m Model) visibleExposure() []firewall.Exposure {
	if m.snapshot == nil {
		return nil
	}
	items := make([]firewall.Exposure, 0, len(m.snapshot.Exposure))
	for _, item := range m.snapshot.Exposure {
		if m.onlyRisky && item.Severity == firewall.SeveritySafe {
			continue
		}
		items = append(items, item)
	}
	sort.SliceStable(items, func(i, j int) bool {
		ri := firewall.SeverityRank(items[i].Severity)
		rj := firewall.SeverityRank(items[j].Severity)
		if ri != rj {
			return ri < rj
		}
		return items[i].Listener.Port < items[j].Listener.Port
	})
	return items
}

// selectedRuleNumber devuelve el número de la regla seleccionada.
func (m Model) selectedRuleNumber() (int, bool) {
	if m.snapshot == nil {
		return 0, false
	}
	cursor := m.rulesTable.Cursor()
	if cursor < 0 || cursor >= len(m.snapshot.Rules) {
		return 0, false
	}
	return m.snapshot.Rules[cursor].Number, true
}

// updateTableFocus mueve el foco a la tabla de la pestaña activa.
func (m *Model) updateTableFocus() {
	m.portsTable.Blur()
	m.rulesTable.Blur()

	switch m.currentTab {
	case tabPorts:
		m.portsTable.Focus()
	case tabRules:
		m.rulesTable.Focus()
	}
}

// toggleRuleCmd habilita o deshabilita una regla.
func (m Model) toggleRuleCmd(number int, enabled bool) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := m.client.SetRuleEnabled(ctx, number, enabled); err != nil {
			return actionResultMsg{err: err}
		}
		verb := "deshabilitada"
		if enabled {
			verb = "habilitada"
		}
		return actionResultMsg{message: fmt.Sprintf("Regla #%d %s", number, verb)}
	}
}

// deleteRuleCmd elimina una regla.
func (m Model) deleteRuleCmd(number int) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := m.client.DeleteRule(ctx, number); err != nil {
			return actionResultMsg{err: err}
		}
		return actionResultMsg{message: fmt.Sprintf("Regla #%d eliminada", number)}
	}
}

// confirmNumber extrae el número de "regla #12".
func confirmNumber(text string) int {
	idx := strings.LastIndex(text, "#")
	if idx < 0 {
		return 0
	}
	number, err := strconv.Atoi(text[idx+1:])
	if err != nil {
		return 0
	}
	return number
}

// View renderiza la interfaz.
func (m Model) View() string {
	if m.form != nil {
		return m.form.view(m.width)
	}

	var s strings.Builder

	// Cabecera.
	header := titleStyle.Render(" 🛡️  PORTS TUI  ")
	daemonInfo := lipgloss.NewStyle().Foreground(mutedColor).Render(fmt.Sprintf(" %s ", m.daemon))
	firewallBadge := ""
	if m.snapshot != nil && m.snapshot.UFW != nil {
		if m.snapshot.UFW.Active {
			firewallBadge = badgeActiveStyle.Render(" UFW ACTIVO ")
		} else {
			firewallBadge = badgeInactiveStyle.Render(" UFW INACTIVO ")
		}
	}
	s.WriteString(lipgloss.JoinHorizontal(lipgloss.Center, header, daemonInfo, firewallBadge) + "\n\n")

	// Tarjetas de resumen.
	if m.snapshot != nil {
		summary := m.snapshot.Summary
		card := func(label, value string, color lipgloss.Color) string {
			return statBoxStyle.Render(fmt.Sprintf("%s\n%s",
				statLabelStyle.Render(label),
				lipgloss.NewStyle().Foreground(color).Bold(true).Render(value)))
		}
		cards := lipgloss.JoinHorizontal(lipgloss.Top,
			card("ESCUCHAS", strconv.Itoa(summary.TotalListeners), highlightColor),
			" ",
			card("PÚBLICOS", strconv.Itoa(summary.PublicListeners), warningColor),
			" ",
			card("EXPUESTOS", strconv.Itoa(summary.ExposedPorts), dangerColor),
			" ",
			card("BLOQUEADOS", strconv.Itoa(summary.BlockedPorts), successColor),
			" ",
			card("REGLAS", strconv.Itoa(summary.TotalRules), secondaryColor),
		)
		s.WriteString(cards + "\n\n")
	}

	// Pestañas.
	tab1 := tabInactiveStyle.Render("1. Escuchas")
	tab2 := tabInactiveStyle.Render("2. Reglas UFW")
	tab3 := tabInactiveStyle.Render("3. Estado")
	switch m.currentTab {
	case tabPorts:
		tab1 = tabActiveStyle.Render("1. Escuchas")
	case tabRules:
		tab2 = tabActiveStyle.Render("2. Reglas UFW")
	case tabStatus:
		tab3 = tabActiveStyle.Render("3. Estado")
	}
	filter := lipgloss.NewStyle().Foreground(mutedColor).Render(" [f: filtro de riesgo]")
	if m.onlyRisky {
		filter = lipgloss.NewStyle().Foreground(warningColor).Render(" [f: solo con riesgo]")
	}
	s.WriteString(lipgloss.JoinHorizontal(lipgloss.Center, tab1, tab2, tab3, filter) + "\n\n")

	// Cuerpo.
	switch m.currentTab {
	case tabPorts:
		s.WriteString(m.portsTable.View())
	case tabRules:
		s.WriteString(m.rulesTable.View())
	case tabStatus:
		s.WriteString(m.renderStatusTab())
	}

	// Mensaje de estado.
	s.WriteString("\n")
	if m.statusMsg != "" {
		if m.isError {
			s.WriteString(statusErrStyle.Render("● "+m.statusMsg) + "\n")
		} else {
			s.WriteString(statusMsgStyle.Render("✔ "+m.statusMsg) + "\n")
		}
	} else if m.loading {
		s.WriteString(lipgloss.NewStyle().Foreground(warningColor).Render("⟳ Consultando al daemon...") + "\n")
	}

	// Ayuda.
	help := fmt.Sprintf(
		"%s: Navegar | %s: Pestaña | %s: Abrir | %s: Cerrar | %s: Eliminar | %s: Refrescar | %s: Salir",
		helpKeyStyle.Render("↑/↓"),
		helpKeyStyle.Render("Tab"),
		helpKeyStyle.Render("o"),
		helpKeyStyle.Render("c"),
		helpKeyStyle.Render("x"),
		helpKeyStyle.Render("R"),
		helpKeyStyle.Render("q"),
	)
	s.WriteString(helpBarStyle.Render(help))

	return s.String()
}

// renderStatusTab muestra el detalle del firewall y las reglas huérfanas.
func (m Model) renderStatusTab() string {
	if m.snapshot == nil {
		return lipgloss.NewStyle().Foreground(mutedColor).Render("Sin datos todavía.")
	}

	var s strings.Builder
	ufwStatus := m.snapshot.UFW
	if ufwStatus != nil {
		s.WriteString(statBoxStyle.Render(fmt.Sprintf("%s\n%s\n%s\n%s",
			statLabelStyle.Render("ESTADO"),
			lipgloss.NewStyle().Foreground(highlightColor).Bold(true).Render(boolLabel(ufwStatus.Active)),
			statLabelStyle.Render("POLÍTICA ENTRADA"),
			lipgloss.NewStyle().Foreground(warningColor).Render(ufwStatus.DefaultIncoming),
		)) + "\n\n")
	}

	if len(m.snapshot.OrphanRules) == 0 {
		s.WriteString(lipgloss.NewStyle().Foreground(successColor).
			Render("✔ Todas las reglas abiertas corresponden a un proceso que escucha") + "\n")
		return s.String()
	}

	s.WriteString(lipgloss.NewStyle().Foreground(warningColor).
		Render(fmt.Sprintf("⚠ %d regla(s) abiertas sin proceso escuchando:", len(m.snapshot.OrphanRules))) + "\n")
	for _, orphan := range m.snapshot.OrphanRules {
		s.WriteString(fmt.Sprintf("  %s %s  %s\n",
			lipgloss.NewStyle().Foreground(mutedColor).Render(fmt.Sprintf("#%d", orphan.Rule.Number)),
			orphan.Reason,
			lipgloss.NewStyle().Foreground(mutedColor).Render(orphan.Rule.Comment)))
	}
	return s.String()
}

// boolLabel traduce un booleano a texto legible.
func boolLabel(value bool) string {
	if value {
		return "activo"
	}
	return "inactivo"
}
