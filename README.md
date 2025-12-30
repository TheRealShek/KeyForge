# Keyforge

Production-grade terminal password manager with industry-standard encryption and security practices.

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

### Security
- **AES-256-GCM encryption** with authenticated encryption
- **PBKDF2-SHA256** key derivation (310,000 iterations)
- **Constant-time comparisons** for secret verification (prevents timing attacks)
- **Atomic vault writes** (temp file + fsync + rename)
- **Opaque cryptographic keys** with explicit zeroing
- **Mutex-protected** vault operations (thread-safe)
- **Signal handling** (SIGINT/SIGTERM) for cleanup on exit
- **Auto-lock** after 5 minutes inactivity
- **Clipboard auto-clear** after 30 seconds (single-timer, no goroutine leaks)

### Dual Authentication
- Master password + recovery code
- Both encryptions updated together (no desync)
- Recovery code stored as verification hash

### Storage
- Local-only encrypted vault (`~/.keyforge.vault`)
- **Vault format versioning** for future crypto migration
- **Stable credential IDs** (UUID-based, not index-based)
- Export encrypted backups

### User Interface
- Clean TUI using Bubble Tea
- Search/filter credentials (handles uppercase correctly)
- **Confirmation dialogs** for destructive actions
- Vim-style keybindings (j/k navigation)
- Password masking
- Real-time search

## Vault Format

```json
{
  "version": 1,
  "master_salt": "...",
  "recovery_salt": "...",
  "master_data": "...",
  "recovery_data": "...",
  "recovery_hash": "..."
}
```

- **Version field**: Enables future crypto algorithm migration
- **Dual encryption**: Vault can be unlocked with either master password or recovery code
- **Separate salts**: Each key derivation uses unique random salt (32 bytes)
- **Unique nonces**: Each AES-GCM encryption uses a fresh 12-byte nonce
- **Recovery hash**: Stored for constant-time verification (prevents brute-force)

Each credential stored with:
- Stable UUID identifier
- Site, password (required)
- Email OR username (at least one required)
- Created/modified timestamps

## Security Improvements (Post-Refactor)

### Fixed Critical Issues
1. ✅ **Atomic writes**: Vault never left in corrupted state (temp file + fsync + atomic rename)
2. ✅ **Race conditions eliminated**: Mutex protects all vault operations
3. ✅ **Recovery encryption fixed**: Both master and recovery encryptions updated together
4. ✅ **Constant-time comparison**: Uses `crypto/subtle` to prevent timing attacks
5. ✅ **Goroutine leaks fixed**: Single-timer clipboard manager, message-based recovery code timeout
6. ✅ **Signal handling**: Cleans up keys and clipboard on SIGINT/SIGTERM
7. ✅ **Opaque keys**: Cryptographic material not exposed, explicitly destroyed

### Architecture Improvements
1. ✅ **Modular design**: Code split into logical packages (crypto, vault, clipboard, ui)
2. ✅ **Screen separation**: UI split into screen-specific files (600+ lines reduced to <200 each)
3. ✅ **Stable IDs**: Credentials identified by UUID, not fragile array indices
4. ✅ **Immutable returns**: Vault getters return copies, not mutable references
5. ✅ **In-memory vault state**: Never re-reads file during save (performance + correctness)
6. ✅ **Wrapped errors**: Error chains preserved with `%w` for better debugging
7. ✅ **Confirmation dialogs**: Destructive actions require explicit confirmation

### Testing
```bash
# Run all tests
go test ./...

# Run specific package tests
go test ./crypto -v
go test ./vault -v
go test ./clipboard -v

# Run with coverage
go test ./... -cover
```

## Security Considerations

### What This Protects Against
✅ **Offline attacks** - Encrypted vault with strong KDF  
✅ **Timing attacks** - Constant-time secret comparison  
✅ **Clipboard monitoring** - Auto-clear after 30s  
✅ **Shoulder surfing** - Password masking  
✅ **Session hijacking** - Auto-lock after inactivity  
✅ **Accidental file corruption** - Atomic writes  
✅ **Race conditions** - Mutex-protected operations  
✅ **Memory dumps** (partially) - Keys explicitly zeroed  

### What This Does NOT Protect Against
✗ **Keyloggers** - OS-level malware can capture input  
✗ **Memory dumps while unlocked** - Vault data in memory  
✗ **Compromised terminal** - Malicious terminal emulator  
✗ **Cloud sync** - No multi-device support (by design)  
✗ **Brute-force weak passwords** - Use strong master password  

### Threat Model

**Adversary capabilities assumed**:
- Can read vault file from disk (encrypted)
- Can observe program behavior timing (mitigated by constant-time comparison)
- Can attempt brute-force on weak passwords (mitigated by PBKDF2 310k iterations)
- Can corrupt filesystem during write (mitigated by atomic writes)

**Trust assumptions**:
- Operating system is not compromised
- Terminal emulator is trustworthy
- Standard library crypto is correctly implemented
- User stores recovery code securely offline

### Best Practices

1. **Strong master password**: 16+ characters, mixed case, numbers, symbols
2. **Store recovery code offline**: Paper backup in secure location (not in cloud)
3. **Export backups regularly**: `x` key to export encrypted backup
4. **Lock screen when away**: Vault auto-locks but don't rely solely on timeout
5. **Keep system updated**: Security patches for OS and terminal
6. **Never share credentials**: Master password and recovery code are secrets
7. **Use unique passwords**: Don't reuse master password elsewhere

### Why These Design Choices?

**PBKDF2 vs Argon2**: PBKDF2 is in Go standard library, has 15+ years of cryptanalysis, and with 310k iterations provides adequate security. Argon2 is better but requires external dependency.

**Local-only storage**: Cloud sync adds attack surface (network interception, cloud provider breach). For single-device use, local storage is more secure.

**Dual encryption**: Recovery code provides disaster recovery without weakening security (both use same KDF strength).

**Mutex over channels**: For vault operations, mutex is simpler and sufficient. No need for actor model complexity.

**UUID vs auto-increment**: UUIDs prevent fragile index-based bugs when filtering/sorting credentials.

## Performance Notes

- **Vault unlock**: ~0.5s (PBKDF2 310k iterations intentionally slow for security)
- **Save operations**: Atomic writes add ~5-10ms overhead (worth it for safety)
- **Search**: O(n) linear scan (acceptable for <10k credentials)
- **Memory**: ~2-5MB typical usage (credentials cached in memory while unlocked)

## Limitations

- **Single vault** per system (no multiple vaults)
- **No password generation** (use external tool like `pwgen`)
- **No 2FA/TOTP** support
- **No secure notes** or file attachments
- **No password history** tracking
- **No breach checking** (no network calls)
- **No auto-fill** browser integration

## Future Enhancements

Potential improvements (not implemented):
- Argon2id support (with version migration)
- Multiple vault support
- Password strength meter
- Password generation
- Breach checking (Have I Been Pwned API)
- Configuration file support
- CLI mode for scripting
- Export to 1Password/Bitwarden format

## License

Open source - use at your own risk. This is secure for personal use but comes with no warranty.

## Contributing

This is a production-refactored example. Key areas for contribution:
- Additional test coverage (currently basic)
- Performance benchmarks
- Security audit
- Additional vault formats (KeePass compatibility)
- Password generation with entropy calculation
