package ui

import (
	"fmt"
	"keyforge/vault"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// ListScreen displays all credentials with search functionality.
type ListScreen struct {
	ctx           *Context
	credentials   []vault.Credential
	filtered      []vault.Credential
	selectedIndex int
	searchQuery   string
	searchActive  bool
	errorMsg      string
	successMsg    string
	pendingPhrase string
}

// NewListScreen creates a new credential list screen.
func NewListScreen(ctx *Context) *ListScreen {
	s := &ListScreen{
		ctx:           ctx,
		selectedIndex: 0,
	}

	if ctx != nil && ctx.Vault != nil {
		s.pendingPhrase = ctx.Vault.ConsumePendingRecoveryPhrase()
	}

	s.loadCredentials()
	return s
}

func (s *ListScreen) loadCredentials() {
	if s.ctx.Vault != nil {
		s.credentials = s.ctx.Vault.GetAllCredentials()
		s.filterCredentials()
	}
}

func (s *ListScreen) filterCredentials() {
	if s.searchQuery == "" {
		s.filtered = s.credentials
	} else {
		s.filtered = s.ctx.Vault.SearchCredentials(s.searchQuery)
	}
	if s.selectedIndex >= len(s.filtered) {
		s.selectedIndex = len(s.filtered) - 1
	}
	if s.selectedIndex < 0 {
		s.selectedIndex = 0
	}
}

func (s *ListScreen) Update(msg tea.Msg) (Screen, tea.Cmd) {
	s.errorMsg = ""
	s.successMsg = ""

	switch msg := msg.(type) {
	case tea.KeyMsg:
		if s.pendingPhrase != "" {
			s.errorMsg = ""
			s.successMsg = ""
			if msg.String() == "enter" {
				s.pendingPhrase = ""
			}
			return s, nil
		}

		// Search mode handling
		if s.searchActive {
			switch msg.String() {
			case "esc":
				s.searchActive = false
				s.searchQuery = ""
				s.filterCredentials()
				return s, nil
			case "enter":
				s.searchActive = false
				return s, nil
			case "backspace":
				if len(s.searchQuery) > 0 {
					s.searchQuery = s.searchQuery[:len(s.searchQuery)-1]
					s.filterCredentials()
				}
				return s, nil
			default:
				// Handle normal character input including uppercase
				key := msg.String()
				if len(key) == 1 || (len(key) > 1 && key[0] != 'c' && key[0] != 's') {
					// Add character to search (handle shift+letter properly)
					if msg.Type == tea.KeyRunes && len(msg.Runes) > 0 {
						s.searchQuery += string(msg.Runes)
						s.filterCredentials()
					}
				}
				return s, nil
			}
		}

		// Normal mode commands
		switch msg.String() {
		case "a":
			return NewAddScreen(s.ctx), nil

		case "e":
			if len(s.filtered) > 0 {
				cred := s.filtered[s.selectedIndex]
				return NewEditScreen(s.ctx, cred.ID), nil
			}

		case "d":
			if len(s.filtered) > 0 {
				cred := s.filtered[s.selectedIndex]
				return NewConfirmScreen(s.ctx, ConfirmDelete, cred.ID, s), nil
			}

		case "c":
			if len(s.filtered) > 0 && s.ctx.ClipboardManager != nil {
				cred := s.filtered[s.selectedIndex]
				if err := s.ctx.ClipboardManager.Copy(cred.Password, s.ctx.Config.ClipboardTimeout); err != nil {
					s.errorMsg = fmt.Sprintf("Error copying: %v", err)
				} else {
					timeout := int(s.ctx.Config.ClipboardTimeout.Seconds())
					s.successMsg = fmt.Sprintf("Password copied (auto-clear in %ds)", timeout)
				}
				return s, nil
			}

		case "m":
			return NewChangeMasterScreen(s.ctx, s), nil

		case "x":
			return NewExportScreen(s.ctx, s), nil

		case "/":
			s.searchActive = true
			s.searchQuery = ""
			return s, nil

		case "up", "k":
			if s.selectedIndex > 0 {
				s.selectedIndex--
			}

		case "down", "j":
			if s.selectedIndex < len(s.filtered)-1 {
				s.selectedIndex++
			}

		case "esc":
			s.searchQuery = ""
			s.filterCredentials()
		}
	}

	return s, nil
}

func (s *ListScreen) View() string {
	var b strings.Builder

	b.WriteString(TitleStyle.Render("🔐 Keyforge - Vault"))
	b.WriteString("\n\n")

	// Search indicator
	if s.searchActive {
		b.WriteString(HighlightStyle.Render("Search: ") + s.searchQuery + "▊\n\n")
	} else if s.searchQuery != "" {
		b.WriteString(fmt.Sprintf("Search: %s (press / to modify, Esc to clear)\n\n", s.searchQuery))
	}

	if s.pendingPhrase != "" {
		b.WriteString(HighlightStyle.Render("Recovery phrase (write down now, press Enter to dismiss):"))
		b.WriteString("\n")
		b.WriteString(SuccessStyle.Render(s.pendingPhrase))
		b.WriteString("\n\n")
	}

	// Credential list
	if len(s.filtered) == 0 {
		if s.searchQuery != "" {
			b.WriteString("No credentials match your search.\n")
		} else {
			b.WriteString("No credentials stored. Press 'a' to add one.\n")
		}
	} else {
		for i, cred := range s.filtered {
			line := fmt.Sprintf("%s (%s)", cred.Site, cred.Identity())
			if i == s.selectedIndex {
				b.WriteString(SelectedItemStyle.Render("► " + line))
			} else {
				b.WriteString(ItemStyle.Render("  " + line))
			}
			b.WriteString("\n")
		}
	}

	b.WriteString("\n")
	if s.searchActive {
		b.WriteString(HelpStyle.Render("Type to search • Enter/Esc to exit search"))
	} else {
		b.WriteString(HelpStyle.Render("a:add • e:edit • d:delete • c:copy password • m:change master • x:export • /:search • ↑↓/j/k:navigate"))
	}

	if s.errorMsg != "" {
		b.WriteString("\n\n")
		b.WriteString(ErrorStyle.Render("✗ " + s.errorMsg))
	}

	if s.successMsg != "" {
		b.WriteString("\n\n")
		b.WriteString(SuccessStyle.Render("✓ " + s.successMsg))
	}

	return b.String()
}
