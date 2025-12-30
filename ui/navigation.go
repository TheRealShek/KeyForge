package ui

import (
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

// NavigateInputs handles tab/shift+tab navigation across text inputs.
// Returns the new cursor position and whether to submit the form.
func NavigateInputs(msg tea.KeyMsg, cursor int, inputCount int) (newCursor int, submit bool) {
	switch msg.String() {
	case "tab":
		return (cursor + 1) % inputCount, false
	case "shift+tab":
		newCursor = cursor - 1
		if newCursor < 0 {
			newCursor = inputCount - 1
		}
		return newCursor, false
	case "enter":
		if cursor == inputCount-1 {
			return cursor, true
		}
		return (cursor + 1) % inputCount, false
	}
	return cursor, false
}

// FocusInput focuses the specified input and blurs all others.
func FocusInput(inputs []textinput.Model, cursor int) {
	for i := range inputs {
		if i == cursor {
			inputs[i].Focus()
		} else {
			inputs[i].Blur()
		}
	}
}

// ClearInputs resets all input values.
func ClearInputs(inputs []textinput.Model) {
	for i := range inputs {
		inputs[i].SetValue("")
	}
}
