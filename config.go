package main

import (
"time"
)

type Config struct {
InactivityTimeout time.Duration
ClipboardTimeout  time.Duration
PBKDF2Iterations  int
}

func DefaultConfig() *Config {
return &Config{
InactivityTimeout: 5 * time.Minute,
ClipboardTimeout:  30 * time.Second,
PBKDF2Iterations:  310000,
}
}
