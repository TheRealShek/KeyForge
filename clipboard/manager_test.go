package clipboard

import (
	"testing"
	"time"
)

func TestManagerCopy(t *testing.T) {
	m := NewManager()
	defer m.Close()

	text := "test-secret"
	timeout := 100 * time.Millisecond

	if err := m.Copy(text, timeout); err != nil {
		t.Fatalf("Copy() error = %v", err)
	}

	// Wait for auto-clear
	time.Sleep(150 * time.Millisecond)

	// Note: Can't reliably test clipboard content in CI environments
	// This test mainly ensures no panics or errors occur
}

func TestManagerClearNow(t *testing.T) {
	m := NewManager()
	defer m.Close()

	m.Copy("test", 1*time.Minute)

	if err := m.ClearNow(); err != nil {
		t.Fatalf("ClearNow() error = %v", err)
	}
}

func TestManagerMultipleCopies(t *testing.T) {
	m := NewManager()
	defer m.Close()

	// Rapidly copy multiple times - should not leak goroutines
	for i := 0; i < 10; i++ {
		if err := m.Copy("test", 1*time.Second); err != nil {
			t.Fatalf("Copy() iteration %d error = %v", i, err)
		}
	}

	m.ClearNow()
}
