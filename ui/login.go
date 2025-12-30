package ui

import (
	"keyforge/vault"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

// LoginScreen handles user authentication.
type LoginScreen struct {
	input    textinput.Model
	errorMsg string
	config   *Config
}

// NewLoginScreen creates a new login screen.
func NewLoginScreen(config *Config) *LoginScreen {
	input := textinput.New()
	input.Placeholder = "Master password or recovery code"
	input.EchoMode = textinput.EchoPassword
	input.Focus()

	return &LoginScreen{
		input:  input,
		config: config,
	}
}

func (s *LoginScreen) Update(msg tea.Msg) (Screen, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "enter":
			password := s.input.Value()
			if password == "" {
				s.errorMsg = "Password cannot be empty"
				return s, nil
			}

			// Try master password first, then recovery code
			v, err := vault.OpenVault(password, false, 310000)
			if err != nil {
				v, err = vault.OpenVault(password, true, 310000)
				if err != nil {
					s.errorMsg = "Invalid password or recovery code"
					s.input.SetValue("")
					return s, nil
				}
			}

			// Successfully logged in
			ctx := &Context{
				Vault:  v,
				Config: s.config,
			}
			return NewListScreen(ctx), nil
		}
	}

	var cmd tea.Cmd
	s.input, cmd = s.input.Update(msg)
	return s, cmd
}

func (s *LoginScreen) View() string {
	var b strings.Builder

	b.WriteString(TitleStyle.Render("🔐 Keyforge - Password Manager"))
	b.WriteString("\n\n")
	b.WriteString(s.input.View())
	b.WriteString("\n\n")
	b.WriteString(HelpStyle.Render("Press Enter to login • Ctrl+C to quit"))

	if s.errorMsg != "" {
		b.WriteString("\n\n")
		b.WriteString(ErrorStyle.Render("✗ " + s.errorMsg))
	}

	return b.String()
}
