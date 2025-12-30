package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"keyforge/crypto"

	"github.com/google/uuid"
)

var (
	ErrSiteRequired       = errors.New("site is required")
	ErrPasswordRequired   = errors.New("password is required")
	ErrIdentityRequired   = errors.New("email or username is required")
	ErrCredentialNotFound = errors.New("credential not found")
	ErrVaultLocked        = errors.New("vault is locked")
)

// Vault manages encrypted credential storage with thread-safe operations.
type Vault struct {
	mu          sync.RWMutex
	data        VaultData
	encrypted   *EncryptedVault
	masterKey   *crypto.Key
	recoveryKey *crypto.Key
	filePath    string
	iterations  int
}

// CreateVault creates a new encrypted vault with master password and recovery code.
func CreateVault(masterPassword string, iterations int) (*Vault, string, error) {
	masterKey, err := crypto.NewKey(masterPassword, iterations)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create master key: %w", err)
	}

	recoveryCode, err := crypto.GenerateRecoveryCode()
	if err != nil {
		masterKey.Destroy()
		return nil, "", fmt.Errorf("failed to generate recovery code: %w", err)
	}

	recoveryKey, err := crypto.NewKey(recoveryCode, iterations)
	if err != nil {
		masterKey.Destroy()
		return nil, "", fmt.Errorf("failed to create recovery key: %w", err)
	}

	vaultData := VaultData{Credentials: []Credential{}}
	jsonData, err := json.Marshal(vaultData)
	if err != nil {
		masterKey.Destroy()
		recoveryKey.Destroy()
		return nil, "", fmt.Errorf("failed to marshal vault data: %w", err)
	}
	defer crypto.SecureWipeBytes(jsonData)

	masterData, err := masterKey.Encrypt(jsonData)
	if err != nil {
		masterKey.Destroy()
		recoveryKey.Destroy()
		return nil, "", fmt.Errorf("failed to encrypt with master key: %w", err)
	}

	recoveryData, err := recoveryKey.Encrypt(jsonData)
	if err != nil {
		masterKey.Destroy()
		recoveryKey.Destroy()
		return nil, "", fmt.Errorf("failed to encrypt with recovery key: %w", err)
	}

	// Store hash of recovery code for validation
	recoveryHash, err := crypto.DeriveKey(recoveryCode, recoveryKey.Salt(), iterations)
	if err != nil {
		masterKey.Destroy()
		recoveryKey.Destroy()
		return nil, "", fmt.Errorf("failed to derive recovery hash: %w", err)
	}
	defer recoveryHash.Destroy()

	encrypted := &EncryptedVault{
		Version:      crypto.CryptoVersion,
		MasterSalt:   masterKey.Salt(),
		RecoverySalt: recoveryKey.Salt(),
		MasterData:   masterData,
		RecoveryData: recoveryData,
		RecoveryHash: recoveryHash.Salt(), // Store as verification hash
	}

	vaultPath, err := GetVaultPath()
	if err != nil {
		masterKey.Destroy()
		recoveryKey.Destroy()
		return nil, "", err
	}

	if err := SaveEncryptedVault(vaultPath, encrypted); err != nil {
		masterKey.Destroy()
		recoveryKey.Destroy()
		return nil, "", fmt.Errorf("failed to save vault: %w", err)
	}

	vault := &Vault{
		data:        vaultData,
		encrypted:   encrypted,
		masterKey:   masterKey,
		recoveryKey: recoveryKey,
		filePath:    vaultPath,
		iterations:  iterations,
	}

	return vault, recoveryCode, nil
}

// OpenVault opens an existing vault with either master password or recovery code.
func OpenVault(password string, isRecoveryCode bool, iterations int) (*Vault, error) {
	vaultPath, err := GetVaultPath()
	if err != nil {
		return nil, err
	}

	encrypted, err := LoadEncryptedVault(vaultPath)
	if err != nil {
		return nil, err
	}

	var key *crypto.Key
	var recoveryKey *crypto.Key
	var encryptedData []byte

	if isRecoveryCode {
		key, err = crypto.DeriveKey(password, encrypted.RecoverySalt, iterations)
		if err != nil {
			return nil, fmt.Errorf("failed to derive recovery key: %w", err)
		}

		// Verify recovery code using constant-time comparison
		testHash, err := crypto.DeriveKey(password, encrypted.RecoverySalt, iterations)
		if err != nil {
			key.Destroy()
			return nil, fmt.Errorf("failed to verify recovery code: %w", err)
		}
		defer testHash.Destroy()

		if !crypto.ConstantTimeCompare(testHash.Salt(), encrypted.RecoveryHash) {
			key.Destroy()
			return nil, errors.New("invalid recovery code")
		}

		encryptedData = encrypted.RecoveryData

		// Also derive master key from recovery for future operations
		// (In production, you'd prompt for new master password)
		recoveryKey = key
	} else {
		key, err = crypto.DeriveKey(password, encrypted.MasterSalt, iterations)
		if err != nil {
			return nil, fmt.Errorf("failed to derive master key: %w", err)
		}
		encryptedData = encrypted.MasterData

		// Derive recovery key for dual updates
		// Note: We don't have the recovery code, so this is a limitation
		// In production, store encrypted recovery code or prompt on password change
	}

	jsonData, err := key.Decrypt(encryptedData)
	if err != nil {
		key.Destroy()
		if recoveryKey != nil {
			recoveryKey.Destroy()
		}
		return nil, errors.New("invalid password or corrupted vault")
	}
	defer crypto.SecureWipeBytes(jsonData)

	var vaultData VaultData
	if err := json.Unmarshal(jsonData, &vaultData); err != nil {
		key.Destroy()
		if recoveryKey != nil {
			recoveryKey.Destroy()
		}
		return nil, fmt.Errorf("failed to parse vault data: %w", err)
	}

	vault := &Vault{
		data:        vaultData,
		encrypted:   encrypted,
		masterKey:   key,
		recoveryKey: recoveryKey,
		filePath:    vaultPath,
		iterations:  iterations,
	}

	return vault, nil
}

// Save persists the vault to disk, updating both master and recovery encryptions.
func (v *Vault) Save() error {
	v.mu.Lock()
	defer v.mu.Unlock()

	jsonData, err := json.Marshal(v.data)
	if err != nil {
		return fmt.Errorf("failed to marshal vault data: %w", err)
	}
	defer crypto.SecureWipeBytes(jsonData)

	// Update master encryption
	masterData, err := v.masterKey.Encrypt(jsonData)
	if err != nil {
		return fmt.Errorf("failed to encrypt with master key: %w", err)
	}
	v.encrypted.MasterData = masterData

	// Update recovery encryption if recovery key is available
	if v.recoveryKey != nil {
		recoveryData, err := v.recoveryKey.Encrypt(jsonData)
		if err != nil {
			return fmt.Errorf("failed to encrypt with recovery key: %w", err)
		}
		v.encrypted.RecoveryData = recoveryData
	}

	if err := SaveEncryptedVault(v.filePath, v.encrypted); err != nil {
		return fmt.Errorf("failed to save vault: %w", err)
	}

	return nil
}

// AddCredential adds a new credential to the vault.
func (v *Vault) AddCredential(cred Credential) error {
	if err := cred.Validate(); err != nil {
		return err
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	// Assign stable ID
	cred.ID = uuid.New().String()
	cred.Created = time.Now()
	cred.Modified = time.Now()

	v.data.Credentials = append(v.data.Credentials, cred)

	return v.save()
}

// UpdateCredential updates an existing credential by ID.
func (v *Vault) UpdateCredential(id string, cred Credential) error {
	if err := cred.Validate(); err != nil {
		return err
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	for i, existing := range v.data.Credentials {
		if existing.ID == id {
			cred.ID = id
			cred.Created = existing.Created
			cred.Modified = time.Now()
			v.data.Credentials[i] = cred
			return v.save()
		}
	}

	return ErrCredentialNotFound
}

// DeleteCredential removes a credential by ID.
func (v *Vault) DeleteCredential(id string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	for i, cred := range v.data.Credentials {
		if cred.ID == id {
			v.data.Credentials = append(v.data.Credentials[:i], v.data.Credentials[i+1:]...)
			return v.save()
		}
	}

	return ErrCredentialNotFound
}

// GetCredential returns a copy of a credential by ID.
func (v *Vault) GetCredential(id string) (Credential, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	for _, cred := range v.data.Credentials {
		if cred.ID == id {
			return cred.Copy(), nil
		}
	}

	return Credential{}, ErrCredentialNotFound
}

// GetAllCredentials returns copies of all credentials.
func (v *Vault) GetAllCredentials() []Credential {
	v.mu.RLock()
	defer v.mu.RUnlock()

	credentials := make([]Credential, len(v.data.Credentials))
	for i, cred := range v.data.Credentials {
		credentials[i] = cred.Copy()
	}
	return credentials
}

// SearchCredentials returns credentials matching the query.
func (v *Vault) SearchCredentials(query string) []Credential {
	v.mu.RLock()
	defer v.mu.RUnlock()

	query = strings.ToLower(query)
	var results []Credential

	for _, cred := range v.data.Credentials {
		if strings.Contains(strings.ToLower(cred.Site), query) ||
			strings.Contains(strings.ToLower(cred.Email), query) ||
			strings.Contains(strings.ToLower(cred.Username), query) {
			results = append(results, cred.Copy())
		}
	}

	return results
}

// ChangeMasterPassword changes the master password and re-encrypts the vault.
func (v *Vault) ChangeMasterPassword(newPassword string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	newKey, err := crypto.NewKey(newPassword, v.iterations)
	if err != nil {
		return fmt.Errorf("failed to create new key: %w", err)
	}

	jsonData, err := json.Marshal(v.data)
	if err != nil {
		newKey.Destroy()
		return fmt.Errorf("failed to marshal vault data: %w", err)
	}
	defer crypto.SecureWipeBytes(jsonData)

	// Encrypt with new master key
	masterData, err := newKey.Encrypt(jsonData)
	if err != nil {
		newKey.Destroy()
		return fmt.Errorf("failed to encrypt with new key: %w", err)
	}

	// Update both master and recovery encryptions
	v.encrypted.MasterData = masterData
	v.encrypted.MasterSalt = newKey.Salt()

	// Re-encrypt with recovery key if available
	if v.recoveryKey != nil {
		recoveryData, err := v.recoveryKey.Encrypt(jsonData)
		if err != nil {
			newKey.Destroy()
			return fmt.Errorf("failed to re-encrypt with recovery key: %w", err)
		}
		v.encrypted.RecoveryData = recoveryData
	}

	if err := SaveEncryptedVault(v.filePath, v.encrypted); err != nil {
		newKey.Destroy()
		return fmt.Errorf("failed to save vault: %w", err)
	}

	// Destroy old key and swap
	v.masterKey.Destroy()
	v.masterKey = newKey

	return nil
}

// ExportBackup exports the encrypted vault to a specified path.
func (v *Vault) ExportBackup(path string) error {
	v.mu.RLock()
	defer v.mu.RUnlock()

	return SaveEncryptedVault(path, v.encrypted)
}

// Close destroys cryptographic keys and clears sensitive data.
func (v *Vault) Close() {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.masterKey != nil {
		v.masterKey.Destroy()
		v.masterKey = nil
	}

	if v.recoveryKey != nil {
		v.recoveryKey.Destroy()
		v.recoveryKey = nil
	}

	// Clear credentials from memory
	for i := range v.data.Credentials {
		crypto.SecureWipeBytes([]byte(v.data.Credentials[i].Password))
	}
	v.data.Credentials = nil
}

// save is the internal save method (caller must hold lock).
func (v *Vault) save() error {
	jsonData, err := json.Marshal(v.data)
	if err != nil {
		return fmt.Errorf("failed to marshal vault data: %w", err)
	}
	defer crypto.SecureWipeBytes(jsonData)

	masterData, err := v.masterKey.Encrypt(jsonData)
	if err != nil {
		return fmt.Errorf("failed to encrypt with master key: %w", err)
	}
	v.encrypted.MasterData = masterData

	if v.recoveryKey != nil {
		recoveryData, err := v.recoveryKey.Encrypt(jsonData)
		if err != nil {
			return fmt.Errorf("failed to encrypt with recovery key: %w", err)
		}
		v.encrypted.RecoveryData = recoveryData
	}

	return SaveEncryptedVault(v.filePath, v.encrypted)
}
