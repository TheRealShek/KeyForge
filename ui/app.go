package ui

import (
	"keyforge/clipboard"
	"keyforge/vault"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// App is the main TUI application model.
type App struct {
	screen           Screen
	ctx              *Context
	clipboardManager *clipboard.Manager
	config           *Config
}

// NewApp creates a new TUI application.
func NewApp(config *Config) *App {
	clipMgr := clipboard.NewManager()

	app := &App{
		clipboardManager: clipMgr,
		config:           config,
		ctx: &Context{
			ClipboardManager: clipMgr,
			Config:           config,
			LastActivity:     time.Now(),
		},
	}

	// Determine initial screen
	exists, err := vault.VaultExists()
	if err != nil || !exists {
		app.screen = NewSetupScreen(config)
	} else {
		app.screen = NewLoginScreen(config)
	}

	return app
}

// Init initializes the application.
func (a *App) Init() tea.Cmd {
	return tea.Batch(
		tickCmd(),
	)
}

func tickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return TickMsg(t)
	})
}

// Update handles messages and updates the application state.
func (a *App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		// Update last activity
		if a.ctx != nil {
			a.ctx.LastActivity = time.Now()
		}

		// Global quit commands
		switch msg.String() {
		case "ctrl+c", "ctrl+q":
			return a, tea.Quit
		}

	case TickMsg:
		// Check for inactivity timeout
		if a.ctx != nil && a.ctx.Vault != nil {
			if time.Since(a.ctx.LastActivity) > a.config.InactivityTimeout {
				// Lock the vault
				a.ctx.Vault.Close()
				a.ctx.Vault = nil
				a.screen = NewLoginScreen(a.config)
				return a, tickCmd()
			}
		}
		return a, tickCmd()
	}

	// Delegate to current screen
	newScreen, cmd := a.screen.Update(msg)

	// Update context if screen changed
	if listScreen, ok := newScreen.(*ListScreen); ok {
		a.ctx = listScreen.ctx
	}

	a.screen = newScreen
	return a, cmd
}

// View renders the application.
func (a *App) View() string {
	return a.screen.View()
}

// Close cleans up resources.
func (a *App) Close() {
	if a.clipboardManager != nil {
		a.clipboardManager.ClearNow()
		a.clipboardManager.Close()
	}
	if a.ctx != nil && a.ctx.Vault != nil {
		a.ctx.Vault.Close()
	}
}
