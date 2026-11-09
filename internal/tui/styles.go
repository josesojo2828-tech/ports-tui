package tui

import (
	"github.com/charmbracelet/lipgloss"
	"github.com/josesojo2828-tech/ports-tui/internal/firewall"
)

// Paleta del tema, alineada con la interfaz web.
var (
	primaryColor   = lipgloss.Color("#3b82f6") // Azul
	secondaryColor = lipgloss.Color("#8b5cf6") // Violeta
	successColor   = lipgloss.Color("#10b981") // Esmeralda
	warningColor   = lipgloss.Color("#f59e0b") // Ámbar
	dangerColor    = lipgloss.Color("#ef4444") // Rojo
	mutedColor     = lipgloss.Color("#64748b") // Pizarra
	highlightColor = lipgloss.Color("#38bdf8") // Celeste
)

// Estilos de la interfaz.
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#ffffff")).
			Background(primaryColor).
			Padding(0, 1)

	tabActiveStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#ffffff")).
			Background(primaryColor).
			Padding(0, 2)

	tabInactiveStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#94a3b8")).
				Padding(0, 2)

	statBoxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#334155")).
			Padding(0, 1).
			Align(lipgloss.Center)

	statLabelStyle = lipgloss.NewStyle().
			Foreground(mutedColor)

	statValueStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(highlightColor)

	statusMsgStyle = lipgloss.NewStyle().
			Foreground(successColor).
			Bold(true)

	statusErrStyle = lipgloss.NewStyle().
			Foreground(dangerColor).
			Bold(true)

	helpBarStyle = lipgloss.NewStyle().
			Foreground(mutedColor).
			MarginTop(1)

	helpKeyStyle = lipgloss.NewStyle().
			Foreground(highlightColor).
			Bold(true)

	badgeActiveStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("#0f172a")).
				Background(successColor).
				Padding(0, 1)

	badgeInactiveStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("#ffffff")).
				Background(dangerColor).
				Padding(0, 1)

	// Estilos del formulario modal.
	formBoxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#3b82f6")).
			Background(lipgloss.Color("#111827")).
			Padding(1, 2)

	formTitleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(highlightColor)

	formLabelStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#94a3b8"))

	formValueStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#e5e7eb"))

	formErrorStyle = lipgloss.NewStyle().
			Foreground(dangerColor).
			Bold(true)

	formHelpStyle = lipgloss.NewStyle().
			Foreground(mutedColor)
)

// severityStyle mapea una severidad a su color.
func severityStyle(severity string) lipgloss.Style {
	switch severity {
	case firewall.SeverityCritical:
		return lipgloss.NewStyle().Foreground(dangerColor).Bold(true)
	case firewall.SeverityHigh:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#fb923c")).Bold(true)
	case firewall.SeverityMedium:
		return lipgloss.NewStyle().Foreground(warningColor)
	case firewall.SeverityLow:
		return lipgloss.NewStyle().Foreground(mutedColor)
	default:
		return lipgloss.NewStyle().Foreground(successColor)
	}
}

// stateIcon devuelve el icono asociado a un estado de exposición.
func stateIcon(state string) string {
	switch state {
	case firewall.StateExposed:
		return "🔴"
	case firewall.StateRestricted:
		return "🟠"
	case firewall.StateBlocked, firewall.StateDefaultBlocked:
		return "🟢"
	case firewall.StateDefaultAllowed:
		return "🔴"
	case firewall.StateNoFirewall:
		return "⚠️"
	case firewall.StateLocal:
		return "⚪"
	default:
		return "•"
	}
}
