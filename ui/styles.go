package ui

import (
	"github.com/charmbracelet/lipgloss"
)

var (
	TitleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("205")).
			MarginBottom(1)

	ErrorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("196"))

	SuccessStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("42"))

	ItemStyle = lipgloss.NewStyle().
			PaddingLeft(2)

	SelectedItemStyle = lipgloss.NewStyle().
				Background(lipgloss.Color("62")).
				PaddingLeft(2)

	HelpStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("241")).
			MarginTop(1)

	InputStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("63")).
			Padding(0, 1)

	HighlightStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("170")).
			Bold(true)
)
