# Keyforge

Secure terminal password manager with AES-256-GCM encryption and recovery phrase support.

## Architecture

```
keyforge/
├── main.go                    # Entry point with signal handling
├── config.go                  # Configuration management
├── version.go                 # Version info
├── crypto/                    # Cryptographic operations
│   ├── crypto.go             # AES-256-GCM, PBKDF2, key management
│   └── crypto_test.go        # Crypto tests
├── vault/                     # Secure credential storage
│   ├── vault.go              # Thread-safe vault with mutex
│   ├── credential.go         # Credential model with stable IDs
│   ├── storage.go            # Atomic file operations
│   └── vault_test.go         # Vault tests
├── clipboard/                 # Clipboard management
│   ├── manager.go            # Single-timer clipboard with auto-clear
│   └── manager_test.go       # Clipboard tests
└── ui/                        # Terminal user interface
    ├── app.go                # Main TUI coordinator
    ├── screen.go             # Screen interface
    ├── login.go              # Login screen
    ├── setup.go              # Initial setup
    ├── list.go               # Credential list with search
    ├── form.go               # Add/edit/export forms
    ├── confirm.go            # Confirmation dialogs
    ├── navigation.go         # Shared navigation logic
    └── styles.go             # Lipgloss styles
```

## Build

```bash
go mod download
go build -o keyforge
```

## Install

```bash
go install
```

Or copy the binary to your PATH:
```bash
sudo cp keyforge /usr/local/bin/
```

## Run

```bash
./keyforge

# Show version
./keyforge --version

# Show help
./keyforge --help
```

## Features

- **AES-256-GCM encryption** with PBKDF2-SHA256 (310K iterations)
- **Recovery phrase system** (12-word BIP39, reset-only, never stored)
- **Vault key wrapping** (dual encryption with master + recovery keys)
- **Atomic writes** with fsync (no corruption)
- **Auto-lock** after 5 minutes, clipboard auto-clear after 30s
- **Thread-safe** operations with mutex protection
- **Stable UUIDs** for credentials
- **Search/filter** with vim-style navigation (j/k)
- **Confirmation dialogs** for destructive actions

## Vault Format (v2)

```json
{
  "version": 2,
  "iterations": 310000,
  "master_salt": "...",
  "recovery_salt": "...",
  "master_wrap": "...",
  "recovery_wrap": "...",
  "vault_ciphertext": "..."
}
```

**Key design:**
- Vault key encrypts all credentials (AES-256-GCM)
- Master key wraps vault key (unlocks vault)
- Recovery key wraps vault key (enables reset)
- Recovery phrase (12 words) shown once at setup
- Migration from v1 generates new recovery phrase automatically

## Security

**Protects against:**
- Offline attacks (strong KDF, 310K iterations)
- Timing attacks (constant-time comparison)
- File corruption (atomic writes)
- Session hijacking (auto-lock)

**Does NOT protect against:**
- Keyloggers or compromised OS
- Memory dumps while unlocked
- Weak master passwords

**Recovery semantics:**
- Recovery phrase resets master password (does not unlock vault directly)
- Old master password invalidated after recovery
- Write down recovery phrase and store offline

**Best practices:**
- Use strong master password (16+ chars)
- Store recovery phrase on paper, not digitally
- Export backups regularly (`x` key)
