package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/josesojo2828-tech/ports-tui/internal/ufw"
)

// formModel es el modal para abrir o cerrar un puerto.
type formModel struct {
	parent *Model
	title  string

	inputs []textinput.Model
	labels []string
	focus  int

	proto  string
	action string

	errMsg string
}

// newFormModel crea el formulario con los valores por defecto.
func newFormModel(title, action string) *formModel {
	port := textinput.New()
	port.Placeholder = "22"
	port.CharLimit = 12
	port.Width = 18

	from := textinput.New()
	from.Placeholder = "any"
	from.SetValue("any")
	from.CharLimit = 40
	from.Width = 24

	comment := textinput.New()
	comment.Placeholder = "opcional"
	comment.CharLimit = 60
	comment.Width = 30

	return &formModel{
		title:  title,
		inputs: []textinput.Model{port, from, comment},
		labels: []string{"Puerto", "Origen", "Comentario"},
		proto:  "tcp",
		action: action,
	}
}

// setPort prellena el campo de puerto.
func (f *formModel) setPort(port string) {
	f.inputs[0].SetValue(port)
	f.inputs[0].Focus()
	f.focus = 0
}

// update maneja las teclas del modal.
func (f *formModel) update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyMsg); ok {
		switch key.String() {
		case "esc":
			f.parent.form = nil
			f.parent.statusMsg = "Operación cancelada"
			f.parent.isError = false
			return *f.parent, nil

		case "enter":
			spec, err := f.spec()
			if err != nil {
				f.errMsg = err.Error()
				return *f.parent, nil
			}
			f.errMsg = ""
			f.parent.form = nil
			f.parent.loading = true
			f.parent.isError = false
			f.parent.statusMsg = "Aplicando regla en el daemon..."
			return *f.parent, f.submitCmd(spec)

		case "tab":
			f.focus = (f.focus + 1) % len(f.inputs)
			f.applyFocus()
			return *f.parent, nil

		case "shift+tab":
			f.focus = (f.focus - 1 + len(f.inputs)) % len(f.inputs)
			f.applyFocus()
			return *f.parent, nil

		case "t":
			f.proto = "tcp"
			return *f.parent, nil

		case "u":
			f.proto = "udp"
			return *f.parent, nil

		case "a":
			f.action = "allow"
			return *f.parent, nil

		case "d":
			f.action = "deny"
			return *f.parent, nil
		}
	}

	var cmd tea.Cmd
	f.inputs[f.focus], cmd = f.inputs[f.focus].Update(msg)
	return *f.parent, cmd
}

// applyFocus mueve el foco visual entre los campos.
func (f *formModel) applyFocus() {
	for i := range f.inputs {
		if i == f.focus {
			f.inputs[i].Focus()
		} else {
			f.inputs[i].Blur()
		}
	}
}

// spec construye la especificación de la regla a partir del formulario.
func (f *formModel) spec() (ufw.Spec, error) {
	spec := ufw.Spec{
		Port:    strings.TrimSpace(f.inputs[0].Value()),
		Proto:   f.proto,
		From:    strings.TrimSpace(f.inputs[1].Value()),
		Action:  f.action,
		Comment: strings.TrimSpace(f.inputs[2].Value()),
	}
	if spec.From == "" {
		spec.From = "any"
	}
	spec = spec.Normalize()
	if err := spec.Validate(); err != nil {
		return ufw.Spec{}, err
	}
	return spec, nil
}

// submitCmd envía la regla al daemon.
func (f *formModel) submitCmd(spec ufw.Spec) tea.Cmd {
	client := f.parent.client
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := client.AddRule(ctx, spec); err != nil {
			return actionResultMsg{err: err}
		}
		return actionResultMsg{message: "Regla aplicada: " + spec.Describe()}
	}
}

// view renderiza el modal centrado.
func (f *formModel) view(width int) string {
	var b strings.Builder

	b.WriteString(formTitleStyle.Render(f.title) + "\n\n")

	for i, input := range f.inputs {
		marker := "  "
		if i == f.focus {
			marker = "▸ "
		}
		label := formLabelStyle.Render(fmt.Sprintf("%s%-11s", marker, f.labels[i]))
		b.WriteString(label + " " + input.View() + "\n")
	}

	actionLabel := "permitir"
	if f.action == "deny" {
		actionLabel = "bloquear"
	}
	b.WriteString(formLabelStyle.Render("▸ Acción      ") +
		formValueStyle.Render(actionLabel) +
		formHelpStyle.Render("   [a] permitir  [d] bloquear") + "\n")

	b.WriteString(formLabelStyle.Render("▸ Protocolo   ") +
		formValueStyle.Render(strings.ToUpper(f.proto)) +
		formHelpStyle.Render("   [t] tcp  [u] udp") + "\n")

	if f.errMsg != "" {
		b.WriteString("\n" + formErrorStyle.Render("✖ "+f.errMsg) + "\n")
	}

	b.WriteString("\n" + formHelpStyle.Render(
		"Tab: siguiente campo | Enter: aplicar | Esc: cancelar") + "\n")

	content := formBoxStyle.Render(b.String())

	if width <= 0 {
		return content
	}
	lines := strings.Split(content, "\n")
	pad := (width - lipgloss.Width(content)) / 2
	if pad < 0 {
		pad = 0
	}
	for i, line := range lines {
		lines[i] = strings.Repeat(" ", pad) + line
	}
	return strings.Join(lines, "\n")
}
