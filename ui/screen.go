package ui

import (
	"keyforge/clipboard"
	"keyforge/vault"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// Screen represents a UI screen that can handle updates and render itself.
type Screen interface {
	Update(msg tea.Msg) (Screen, tea.Cmd)
	View() string
}

// ScreenType identifies different screen types.
type ScreenType int

const (
	ScreenTypeLogin ScreenType = iota
	ScreenTypeSetup
	ScreenTypeList
	ScreenTypeAdd
	ScreenTypeEdit
	ScreenTypeChangeMaster
	ScreenTypeExport
	ScreenTypeConfirm
)

// TickMsg is sent every second for inactivity tracking.
type TickMsg time.Time

// LockMsg is sent to lock the vault.
type LockMsg struct{}

// HideRecoveryMsg is sent to hide the recovery code after display timeout.
type HideRecoveryMsg struct{}

// ClipboardClearedMsg is sent when clipboard is auto-cleared.
type ClipboardClearedMsg struct{}

// ConfirmAction represents an action that needs confirmation.
type ConfirmAction int

const (
	ConfirmDelete ConfirmAction = iota
	ConfirmChangeMaster
)

// Context holds shared application state and dependencies.
type Context struct {
	Vault            *vault.Vault
	ClipboardManager *clipboard.Manager
	Config           *Config
	LastActivity     time.Time
}

// Config holds UI configuration.
type Config struct {
	InactivityTimeout time.Duration
	ClipboardTimeout  time.Duration
}
