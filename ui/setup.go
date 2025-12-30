package ui

import (
	"fmt"
	"keyforge/clipboard"
	"keyforge/vault"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

// SetupScreen handles initial vault creation.
type SetupScreen struct {
	inputs           []textinput.Model
	cursor           int
	errorMsg         string
	recoveryCode     string
	config           *Config
	vault            *vault.Vault
	clipboardManager *clipboard.Manager
}

// NewSetupScreen creates a new setup screen.
func NewSetupScreen(config *Config, clipboardManager *clipboard.Manager) *SetupScreen {
	inputs := make([]textinput.Model, 2)

	inputs[0] = textinput.New()
	inputs[0].Placeholder = "Master password"
	inputs[0].EchoMode = textinput.EchoPassword
	inputs[0].Focus()

	inputs[1] = textinput.New()
	inputs[1].Placeholder = "Confirm password"
	inputs[1].EchoMode = textinput.EchoPassword

	return &SetupScreen{
		inputs:           inputs,
		cursor:           0,
		config:           config,
		clipboardManager: clipboardManager,
	}
}

func hideRecoveryAfter(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(t time.Time) tea.Msg {
		return HideRecoveryMsg{}
	})
}

func (s *SetupScreen) Update(msg tea.Msg) (Screen, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		newCursor, submit := NavigateInputs(msg, s.cursor, len(s.inputs))
		if newCursor != s.cursor {
			s.cursor = newCursor
			FocusInput(s.inputs, s.cursor)
			return s, nil
		}

		if submit {
			password := s.inputs[0].Value()
			confirm := s.inputs[1].Value()

			if password == "" {
				s.errorMsg = "Password cannot be empty"
				return s, nil
			}
			if len(password) < 8 {
				s.errorMsg = "Password too short (minimum 8 characters)"
				return s, nil
			}
			if password != confirm {
				s.errorMsg = "Passwords do not match"
				return s, nil
			}
			v, recovery, err := vault.CreateVault(password, 310000)
			if err != nil {
				s.errorMsg = fmt.Sprintf("Error: %v", err)
				return s, nil
			}

			s.recoveryCode = recovery
			s.vault = v

			// Show recovery code for 10 seconds before transitioning
			return s, hideRecoveryAfter(10 * time.Second)
		}

	case HideRecoveryMsg:
		if s.recoveryCode != "" {
			ctx := &Context{
				Vault:            s.vault,
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

func (s *SetupScreen) View() string {
	var b strings.Builder

	b.WriteString(TitleStyle.Render("🔐 Keyforge - Initial Setup"))
	b.WriteString("\n\n")

	for i := range s.inputs {
		b.WriteString(s.inputs[i].View())
		b.WriteString("\n")
	}

	b.WriteString("\n")
	b.WriteString(HelpStyle.Render("Tab/Shift+Tab to navigate • Enter to create • Ctrl+C to quit"))

	if s.recoveryCode != "" {
		b.WriteString("\n\n")
		b.WriteString(HighlightStyle.Render("RECOVERY CODE (save securely):"))
		b.WriteString("\n")
		b.WriteString(SuccessStyle.Render(s.recoveryCode))
		b.WriteString("\n")
		b.WriteString(HelpStyle.Render("This code will disappear in 10 seconds..."))
	}

	if s.errorMsg != "" {
		b.WriteString("\n\n")
		b.WriteString(ErrorStyle.Render("✗ " + s.errorMsg))
	}

	return b.String()
}
