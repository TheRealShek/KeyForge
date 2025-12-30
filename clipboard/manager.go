// Package clipboard provides secure clipboard management with auto-clear functionality.
package clipboard

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/atotto/clipboard"
)

// Manager handles clipboard operations with automatic clearing.
// Uses a single timer to prevent goroutine leaks.
type Manager struct {
	mu    sync.Mutex
	timer *time.Timer
}

// NewManager creates a new clipboard manager.
func NewManager() *Manager {
	return &Manager{}
}

// Copy copies text to clipboard and schedules automatic clearing after timeout.
func (m *Manager) Copy(text string, timeout time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Stop any existing timer
	if m.timer != nil {
		m.timer.Stop()
		m.timer = nil
	}

	// Copy to clipboard
	if err := clipboard.WriteAll(text); err != nil {
		return fmt.Errorf("failed to write to clipboard: %w", err)
	}

	// Schedule auto-clear
	m.timer = time.AfterFunc(timeout, func() {
		if err := clipboard.WriteAll(""); err != nil {
			log.Printf("Warning: failed to clear clipboard: %v", err)
		}
	})

	return nil
}

// ClearNow immediately clears the clipboard and cancels any pending auto-clear.
func (m *Manager) ClearNow() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.timer != nil {
		m.timer.Stop()
		m.timer = nil
	}

	if err := clipboard.WriteAll(""); err != nil {
		return fmt.Errorf("failed to clear clipboard: %w", err)
	}

	return nil
}

// Close stops any pending timers. Should be called on program exit.
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.timer != nil {
		m.timer.Stop()
		m.timer = nil
	}
}
