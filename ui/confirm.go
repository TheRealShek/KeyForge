package ui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// ConfirmScreen displays a confirmation dialog for destructive actions.
type ConfirmScreen struct {
	ctx     *Context
	action  ConfirmAction
	target  string
	parent  Screen
	message string
}

// NewConfirmScreen creates a new confirmation dialog.
func NewConfirmScreen(ctx *Context, action ConfirmAction, target string, parent Screen) *ConfirmScreen {
	var message string
	switch action {
	case ConfirmDelete:
		message = "Delete this credential?"
	case ConfirmChangeMaster:
		message = "Change master password? This cannot be undone."
	default:
		message = "Confirm this action?"
	}

	return &ConfirmScreen{
		ctx:     ctx,
		action:  action,
		target:  target,
		parent:  parent,
		message: message,
	}
}

func (s *ConfirmScreen) Update(msg tea.Msg) (Screen, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "y", "Y":
			return s.performAction()

		case "n", "N", "esc":
			return s.parent, nil
		}
	}

	return s, nil
}

func (s *ConfirmScreen) performAction() (Screen, tea.Cmd) {
	switch s.action {
	case ConfirmDelete:
		if err := s.ctx.Vault.DeleteCredential(s.target); err != nil {
			// Return to parent with error (in real implementation)
			return s.parent, nil
		}
		return NewListScreen(s.ctx), nil

	default:
		return s.parent, nil
	}
}

func (s *ConfirmScreen) View() string {
	var b strings.Builder

	b.WriteString(TitleStyle.Render("⚠️  Confirm Action"))
	b.WriteString("\n\n")
	b.WriteString(HighlightStyle.Render(s.message))
	b.WriteString("\n\n")

	// Show credential being deleted if applicable
	if s.action == ConfirmDelete {
		cred, err := s.ctx.Vault.GetCredential(s.target)
		if err == nil {
			b.WriteString(fmt.Sprintf("Site: %s\n", cred.Site))
			b.WriteString(fmt.Sprintf("Identity: %s\n\n", cred.Identity()))
		}
	}

	b.WriteString(HelpStyle.Render("y: Yes, proceed • n/Esc: No, cancel"))

	return b.String()
}
