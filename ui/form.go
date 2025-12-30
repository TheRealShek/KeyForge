package ui

import (
	"fmt"
	"keyforge/vault"
	"regexp"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

// AddScreen handles adding new credentials.
type AddScreen struct {
	ctx      *Context
	inputs   []textinput.Model
	cursor   int
	errorMsg string
	parent   Screen
}

// NewAddScreen creates a new add credential screen.
func NewAddScreen(ctx *Context) *AddScreen {
	inputs := make([]textinput.Model, 4)

	inputs[0] = textinput.New()
	inputs[0].Placeholder = "Site/Service (e.g., github.com)"
	inputs[0].Focus()

	inputs[1] = textinput.New()
	inputs[1].Placeholder = "Email (optional if username provided)"

	inputs[2] = textinput.New()
	inputs[2].Placeholder = "Username (optional if email provided)"

	inputs[3] = textinput.New()
	inputs[3].Placeholder = "Password"
	inputs[3].EchoMode = textinput.EchoPassword

	return &AddScreen{
		ctx:    ctx,
		inputs: inputs,
		cursor: 0,
	}
}

func (s *AddScreen) Update(msg tea.Msg) (Screen, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			return NewListScreen(s.ctx), nil
		}

		newCursor, submit := NavigateInputs(msg, s.cursor, len(s.inputs))
		if newCursor != s.cursor {
			s.cursor = newCursor
			FocusInput(s.inputs, s.cursor)
			return s, nil
		}

		if submit {
			cred := vault.Credential{
				Site:     strings.TrimSpace(s.inputs[0].Value()),
				Email:    strings.TrimSpace(s.inputs[1].Value()),
				Username: strings.TrimSpace(s.inputs[2].Value()),
				Password: s.inputs[3].Value(),
			}

			// Validate
			if err := s.validate(cred); err != nil {
				s.errorMsg = err.Error()
				return s, nil
			}

			if err := s.ctx.Vault.AddCredential(cred); err != nil {
				s.errorMsg = fmt.Sprintf("Error: %v", err)
				return s, nil
			}

			return NewListScreen(s.ctx), nil
		}
	}

	var cmd tea.Cmd
	s.inputs[s.cursor], cmd = s.inputs[s.cursor].Update(msg)
	return s, cmd
}

func (s *AddScreen) validate(cred vault.Credential) error {
	if cred.Site == "" {
		return fmt.Errorf("site is required")
	}
	if cred.Password == "" {
		return fmt.Errorf("password is required")
	}
	if len(cred.Password) < 6 {
		return fmt.Errorf("password too short (minimum 6 characters)")
	}
	if cred.Email == "" && cred.Username == "" {
		return fmt.Errorf("email or username is required")
	}
	if cred.Email != "" && !emailRegex.MatchString(cred.Email) {
		return fmt.Errorf("invalid email format")
	}
	return nil
}

func (s *AddScreen) View() string {
	var b strings.Builder

	b.WriteString(TitleStyle.Render("➕ Add Credential"))
	b.WriteString("\n\n")

	for i := range s.inputs {
		b.WriteString(s.inputs[i].View())
		b.WriteString("\n")
	}

	b.WriteString("\n")
	b.WriteString(HelpStyle.Render("Tab/Shift+Tab to navigate • Enter to save • Esc to cancel"))

	if s.errorMsg != "" {
		b.WriteString("\n\n")
		b.WriteString(ErrorStyle.Render("✗ " + s.errorMsg))
	}

	return b.String()
}

// EditScreen handles editing existing credentials.
type EditScreen struct {
	ctx      *Context
	credID   string
	inputs   []textinput.Model
	cursor   int
	errorMsg string
}

// NewEditScreen creates a new edit credential screen.
func NewEditScreen(ctx *Context, credID string) *EditScreen {
	cred, err := ctx.Vault.GetCredential(credID)
	if err != nil {
		// If credential not found, return to list
		return &EditScreen{ctx: ctx, credID: credID, errorMsg: "Credential not found"}
	}

	inputs := make([]textinput.Model, 4)

	inputs[0] = textinput.New()
	inputs[0].Placeholder = "Site/Service"
	inputs[0].SetValue(cred.Site)
	inputs[0].Focus()

	inputs[1] = textinput.New()
	inputs[1].Placeholder = "Email"
	inputs[1].SetValue(cred.Email)

	inputs[2] = textinput.New()
	inputs[2].Placeholder = "Username"
	inputs[2].SetValue(cred.Username)

	inputs[3] = textinput.New()
	inputs[3].Placeholder = "Password"
	inputs[3].EchoMode = textinput.EchoPassword
	inputs[3].SetValue(cred.Password)

	return &EditScreen{
		ctx:    ctx,
		credID: credID,
		inputs: inputs,
		cursor: 0,
	}
}

func (s *EditScreen) Update(msg tea.Msg) (Screen, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			return NewListScreen(s.ctx), nil
		}

		newCursor, submit := NavigateInputs(msg, s.cursor, len(s.inputs))
		if newCursor != s.cursor {
			s.cursor = newCursor
			FocusInput(s.inputs, s.cursor)
			return s, nil
		}

		if submit {
			cred := vault.Credential{
				Site:     strings.TrimSpace(s.inputs[0].Value()),
				Email:    strings.TrimSpace(s.inputs[1].Value()),
				Username: strings.TrimSpace(s.inputs[2].Value()),
				Password: s.inputs[3].Value(),
			}

			if err := cred.Validate(); err != nil {
				s.errorMsg = err.Error()
				return s, nil
			}

			if err := s.ctx.Vault.UpdateCredential(s.credID, cred); err != nil {
				s.errorMsg = fmt.Sprintf("Error: %v", err)
				return s, nil
			}

			return NewListScreen(s.ctx), nil
		}
	}

	var cmd tea.Cmd
	s.inputs[s.cursor], cmd = s.inputs[s.cursor].Update(msg)
	return s, cmd
}

func (s *EditScreen) View() string {
	var b strings.Builder

	b.WriteString(TitleStyle.Render("✏️  Edit Credential"))
	b.WriteString("\n\n")

	for i := range s.inputs {
		b.WriteString(s.inputs[i].View())
		b.WriteString("\n")
	}

	b.WriteString("\n")
	b.WriteString(HelpStyle.Render("Tab/Shift+Tab to navigate • Enter to save • Esc to cancel"))

	if s.errorMsg != "" {
		b.WriteString("\n\n")
		b.WriteString(ErrorStyle.Render("✗ " + s.errorMsg))
	}

	return b.String()
}

// ChangeMasterScreen handles changing the master password.
type ChangeMasterScreen struct {
	ctx      *Context
	inputs   []textinput.Model
	cursor   int
	errorMsg string
	parent   Screen
}

// NewChangeMasterScreen creates a new change master password screen.
func NewChangeMasterScreen(ctx *Context, parent Screen) *ChangeMasterScreen {
	inputs := make([]textinput.Model, 2)

	inputs[0] = textinput.New()
	inputs[0].Placeholder = "New master password"
	inputs[0].EchoMode = textinput.EchoPassword
	inputs[0].Focus()

	inputs[1] = textinput.New()
	inputs[1].Placeholder = "Confirm new password"
	inputs[1].EchoMode = textinput.EchoPassword

	return &ChangeMasterScreen{
		ctx:    ctx,
		inputs: inputs,
		cursor: 0,
		parent: parent,
	}
}

func (s *ChangeMasterScreen) Update(msg tea.Msg) (Screen, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			return s.parent, nil
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

			if err := s.ctx.Vault.ChangeMasterPassword(newPassword); err != nil {
				s.errorMsg = fmt.Sprintf("Error: %v", err)
				return s, nil
			}

			return NewListScreen(s.ctx), nil
		}
	}

	var cmd tea.Cmd
	s.inputs[s.cursor], cmd = s.inputs[s.cursor].Update(msg)
	return s, cmd
}

func (s *ChangeMasterScreen) View() string {
	var b strings.Builder

	b.WriteString(TitleStyle.Render("🔑 Change Master Password"))
	b.WriteString("\n\n")

	for i := range s.inputs {
		b.WriteString(s.inputs[i].View())
		b.WriteString("\n")
	}

	b.WriteString("\n")
	b.WriteString(HelpStyle.Render("Tab/Shift+Tab to navigate • Enter to save • Esc to cancel"))

	if s.errorMsg != "" {
		b.WriteString("\n\n")
		b.WriteString(ErrorStyle.Render("✗ " + s.errorMsg))
	}

	return b.String()
}

// ExportScreen handles exporting encrypted backups.
type ExportScreen struct {
	ctx      *Context
	input    textinput.Model
	errorMsg string
	parent   Screen
}

// NewExportScreen creates a new export screen.
func NewExportScreen(ctx *Context, parent Screen) *ExportScreen {
	input := textinput.New()
	input.Placeholder = "Backup file path (e.g., ~/keyforge-backup.vault)"
	input.Focus()

	return &ExportScreen{
		ctx:    ctx,
		input:  input,
		parent: parent,
	}
}

func (s *ExportScreen) Update(msg tea.Msg) (Screen, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			return s.parent, nil
		case "enter":
			path := strings.TrimSpace(s.input.Value())
			if path == "" {
				s.errorMsg = "Path cannot be empty"
				return s, nil
			}

			if err := s.ctx.Vault.ExportBackup(path); err != nil {
				s.errorMsg = fmt.Sprintf("Error: %v", err)
				return s, nil
			}

			return NewListScreen(s.ctx), nil
		}
	}

	var cmd tea.Cmd
	s.input, cmd = s.input.Update(msg)
	return s, cmd
}

func (s *ExportScreen) View() string {
	var b strings.Builder

	b.WriteString(TitleStyle.Render("💾 Export Backup"))
	b.WriteString("\n\n")
	b.WriteString(s.input.View())
	b.WriteString("\n\n")
	b.WriteString(HelpStyle.Render("Enter to export • Esc to cancel"))

	if s.errorMsg != "" {
		b.WriteString("\n\n")
		b.WriteString(ErrorStyle.Render("✗ " + s.errorMsg))
	}

	return b.String()
}
