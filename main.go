package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"keyforge/ui"

	tea "github.com/charmbracelet/bubbletea"
)

var (
	versionFlag = flag.Bool("version", false, "Print version information")
	helpFlag    = flag.Bool("help", false, "Show help")
)

func main() {
	flag.Parse()

	if *versionFlag {
		fmt.Printf("Keyforge v%s\n", Version)
		os.Exit(0)
	}

	if *helpFlag {
		fmt.Println("Keyforge - Secure Terminal Password Manager")
		fmt.Println("\nUsage:")
		fmt.Println("  keyforge [flags]")
		fmt.Println("\nFlags:")
		flag.PrintDefaults()
		os.Exit(0)
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	// Load configuration
	config := DefaultConfig()
	uiConfig := &ui.Config{
		InactivityTimeout: config.InactivityTimeout,
		ClipboardTimeout:  config.ClipboardTimeout,
	}

	// Create TUI application
	app := ui.NewApp(uiConfig)
	defer app.Close()

	// Run app in goroutine to handle signals
	p := tea.NewProgram(app, tea.WithAltScreen(), tea.WithContext(ctx))

	// Handle signals in background
	go func() {
		<-sigCh
		app.Close()
		cancel()
		p.Quit()
	}()

	// Run the program
	if _, err := p.Run(); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}
