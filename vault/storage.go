package vault

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"keyforge/crypto"
)

// EncryptedVault represents the on-disk vault format.
type EncryptedVault struct {
	Version               int    `json:"version"`
	MasterSalt            []byte `json:"master_salt"`
	RecoverySalt          []byte `json:"recovery_salt"`
	MasterData            []byte `json:"master_data"`
	RecoveryData          []byte `json:"recovery_data"`
	RecoveryHash          []byte `json:"recovery_hash"`
	EncryptedRecoveryCode []byte `json:"encrypted_recovery_code"` // Recovery code encrypted with master key
}

// VaultData is the decrypted vault contents.
type VaultData struct {
	Credentials []Credential `json:"credentials"`
}

// saveAtomically writes data to path atomically using temp file + rename.
// This ensures the vault is never left in a corrupted state.
func saveAtomically(path string, data []byte, perm os.FileMode) error {
	// Create temp file in same directory to ensure same filesystem
	dir := filepath.Dir(path)
	tmpFile, err := os.CreateTemp(dir, ".keyforge-*.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	// Clean up temp file on error
	defer func() {
		if tmpFile != nil {
			tmpFile.Close()
			os.Remove(tmpPath)
		}
	}()

	// Write data
	if _, err := tmpFile.Write(data); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	// Sync to disk
	if err := tmpFile.Sync(); err != nil {
		return fmt.Errorf("failed to sync temp file: %w", err)
	}

	// Close before rename
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}
	tmpFile = nil // Prevent defer from closing again

	// Set permissions
	if err := os.Chmod(tmpPath, perm); err != nil {
		return fmt.Errorf("failed to set permissions: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	return nil
}

// SaveEncryptedVault writes an encrypted vault to disk atomically.
func SaveEncryptedVault(path string, vault *EncryptedVault) error {
	jsonData, err := json.MarshalIndent(vault, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal vault: %w", err)
	}

	return saveAtomically(path, jsonData, 0600)
}

// LoadEncryptedVault reads an encrypted vault from disk.
func LoadEncryptedVault(path string) (*EncryptedVault, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read vault: %w", err)
	}

	var vault EncryptedVault
	if err := json.Unmarshal(data, &vault); err != nil {
		return nil, fmt.Errorf("failed to parse vault: %w", err)
	}

	// Validate version
	if vault.Version < 1 || vault.Version > crypto.CryptoVersion {
		return nil, fmt.Errorf("unsupported vault version %d", vault.Version)
	}

	return &vault, nil
}

// GetVaultPath returns the default vault file path.
func GetVaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}
	return filepath.Join(home, ".keyforge.vault"), nil
}

// VaultExists checks if a vault exists at the default path.
func VaultExists() (bool, error) {
	path, err := GetVaultPath()
	if err != nil {
		return false, err
	}
	_, err = os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, fmt.Errorf("failed to check vault: %w", err)
}
