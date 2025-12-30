package ui

import (
	"fmt"
	"strings"
	"time"

	"keyforge/clipboard"
	"keyforge/vault"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

// RecoveryResetScreen handles the recovery-driven master password reset flow.
type RecoveryResetScreen struct {
	session          *vault.RecoverySession
	inputs           []textinput.Model
	cursor           int
	errorMsg         string
	config           *Config
	clipboardManager *clipboard.Manager
}

// NewRecoveryResetScreen creates a new recovery reset screen.
func NewRecoveryResetScreen(session *vault.RecoverySession, config *Config, clipboardManager *clipboard.Manager) *RecoveryResetScreen {
	inputs := make([]textinput.Model, 2)

	inputs[0] = textinput.New()
	inputs[0].Placeholder = "New master password"
	inputs[0].EchoMode = textinput.EchoPassword
	inputs[0].Focus()

	inputs[1] = textinput.New()
	inputs[1].Placeholder = "Confirm new password"
	inputs[1].EchoMode = textinput.EchoPassword

	return &RecoveryResetScreen{
		session:          session,
		inputs:           inputs,
		cursor:           0,
		config:           config,
		clipboardManager: clipboardManager,
	}
}

func (s *RecoveryResetScreen) Update(msg tea.Msg) (Screen, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			return NewLoginScreen(s.config, s.clipboardManager), nil
		}

		newCursor, submit := NavigateInputs(msg, s.cursor, len(s.inputs))
		if newCursor != s.cursor {
			s.cursor = newCursor
			FocusInput(s.inputs, s.cursor)
			return s, nil
		}

		if submit {
			newPassword := s.inputs[0].Value()
			confirm := s.inputs[1].Value()

			if newPassword == "" {
				s.errorMsg = "Password cannot be empty"
				return s, nil
			}
			if len(newPassword) < 8 {
				s.errorMsg = "Password too short (minimum 8 characters)"
				return s, nil
			}
			if newPassword != confirm {
				s.errorMsg = "Passwords do not match"
				return s, nil
			}

			v, err := s.session.Complete(newPassword)
			if err != nil {
				s.errorMsg = fmt.Sprintf("Error: %v", err)
				return s, nil
			}

			ctx := &Context{
				Vault:            v,
				Config:           s.config,
				ClipboardManager: s.clipboardManager,
				LastActivity:     time.Now(),
			}
			return NewListScreen(ctx), nil
		}
	}

	var cmd tea.Cmd
	s.inputs[s.cursor], cmd = s.inputs[s.cursor].Update(msg)
	return s, cmd
}

func (s *RecoveryResetScreen) View() string {
	var b strings.Builder

	b.WriteString(TitleStyle.Render("🔁 Reset Master Password"))
	b.WriteString("\n\n")

	for i := range s.inputs {
		b.WriteString(s.inputs[i].View())
		b.WriteString("\n")
	}

	b.WriteString("\n")
	b.WriteString(HelpStyle.Render("Tab/Shift+Tab to navigate • Enter to reset • Esc to cancel"))

	if s.errorMsg != "" {
		b.WriteString("\n\n")
		b.WriteString(ErrorStyle.Render("✗ " + s.errorMsg))
	}

	return b.String()
}
