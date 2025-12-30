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
	ErrInvalidRecovery    = errors.New("invalid recovery code")
)

// Vault manages encrypted credential storage with thread-safe operations.
type Vault struct {
	mu                    sync.RWMutex
	data                  VaultData
	encrypted             *EncryptedVault
	masterKey             *crypto.Key
	vaultKey              []byte
	filePath              string
	iterations            int
	pendingRecoveryPhrase string
}

// RecoverySession encapsulates a verified recovery attempt that still
// requires the user to set a new master password.
type RecoverySession struct {
	encrypted     *EncryptedVault
	vaultKey      []byte
	filePath      string
	iterations    int
	pendingPhrase string
}

// CreateVault creates a new encrypted vault with a master password and
// returns the recovery phrase (as a space-separated string).
func CreateVault(masterPassword string, iterations int) (*Vault, string, error) {
	masterKey, err := crypto.NewKey(masterPassword, iterations)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create master key: %w", err)
	}

	recoveryWords, err := crypto.GenerateRecoveryPhrase(0)
	if err != nil {
		masterKey.Destroy()
		return nil, "", fmt.Errorf("failed to generate recovery phrase: %w", err)
	}

	recoverySalt, err := crypto.GenerateRandomBytes(32)
	if err != nil {
		masterKey.Destroy()
		return nil, "", fmt.Errorf("failed to create recovery salt: %w", err)
	}

	recoveryKey, err := crypto.DeriveRecoveryKey(recoveryWords, recoverySalt, iterations)
	if err != nil {
		masterKey.Destroy()
		return nil, "", fmt.Errorf("failed to create recovery key: %w", err)
	}

	vaultKey, err := crypto.GenerateRandomBytes(32)
	if err != nil {
		masterKey.Destroy()
		recoveryKey.Destroy()
		return nil, "", fmt.Errorf("failed to generate vault key: %w", err)
	}

	vaultData := VaultData{Credentials: []Credential{}}
	jsonData, err := json.Marshal(vaultData)
	if err != nil {
		masterKey.Destroy()
		recoveryKey.Destroy()
		crypto.SecureWipeBytes(vaultKey)
		return nil, "", fmt.Errorf("failed to marshal vault data: %w", err)
	}
	defer crypto.SecureWipeBytes(jsonData)

	vaultCiphertext, err := crypto.EncryptWithKey(vaultKey, jsonData)
	if err != nil {
		masterKey.Destroy()
		recoveryKey.Destroy()
		crypto.SecureWipeBytes(vaultKey)
		return nil, "", fmt.Errorf("failed to encrypt vault data: %w", err)
	}

	masterWrap, err := masterKey.Encrypt(vaultKey)
	if err != nil {
		masterKey.Destroy()
		recoveryKey.Destroy()
		crypto.SecureWipeBytes(vaultKey)
		return nil, "", fmt.Errorf("failed to wrap vault key with master key: %w", err)
	}

	recoveryWrap, err := recoveryKey.Encrypt(vaultKey)
	if err != nil {
		masterKey.Destroy()
		recoveryKey.Destroy()
		crypto.SecureWipeBytes(vaultKey)
		return nil, "", fmt.Errorf("failed to wrap vault key with recovery key: %w", err)
	}

	encrypted := &EncryptedVault{
		Version:         crypto.CryptoVersion,
		Iterations:      iterations,
		MasterSalt:      masterKey.Salt(),
		RecoverySalt:    recoveryKey.Salt(),
		MasterWrap:      masterWrap,
		RecoveryWrap:    recoveryWrap,
		VaultCiphertext: vaultCiphertext,
	}

	vaultPath, err := GetVaultPath()
	if err != nil {
		masterKey.Destroy()
		recoveryKey.Destroy()
		crypto.SecureWipeBytes(vaultKey)
		return nil, "", err
	}

	if err := SaveEncryptedVault(vaultPath, encrypted); err != nil {
		masterKey.Destroy()
		recoveryKey.Destroy()
		crypto.SecureWipeBytes(vaultKey)
		return nil, "", fmt.Errorf("failed to save vault: %w", err)
	}

	vault := &Vault{
		data:                  vaultData,
		encrypted:             encrypted,
		masterKey:             masterKey,
		vaultKey:              vaultKey,
		filePath:              vaultPath,
		iterations:            iterations,
		pendingRecoveryPhrase: crypto.RecoveryPhraseString(recoveryWords),
	}

	recoveryKey.Destroy()
	return vault, vault.pendingRecoveryPhrase, nil
}

// OpenVault opens an existing vault with the master password.
func OpenVault(masterPassword string, iterations int) (*Vault, error) {
	vaultPath, err := GetVaultPath()
	if err != nil {
		return nil, err
	}

	encrypted, err := LoadEncryptedVault(vaultPath)
	if err != nil {
		return nil, err
	}

	// Handle legacy vaults transparently via migration.
	if encrypted.Version == 1 {
		return migrateFromV1WithMaster(vaultPath, encrypted, masterPassword, iterations)
	}

	return openV2Vault(vaultPath, encrypted, masterPassword, iterations)
}

// BeginRecovery validates a recovery phrase and prepares a reset session.
// It never opens the vault contents directly.
func BeginRecovery(phrase string, iterations int) (*RecoverySession, error) {
	vaultPath, err := GetVaultPath()
	if err != nil {
		return nil, err
	}

	encrypted, err := LoadEncryptedVault(vaultPath)
	if err != nil {
		return nil, err
	}

	if encrypted.Version == 1 {
		return beginRecoveryV1(vaultPath, encrypted, phrase, iterations)
	}

	return beginRecoveryV2(vaultPath, encrypted, phrase, iterations)
}

// Complete finalizes a recovery session by setting a new master password.
func (s *RecoverySession) Complete(newMasterPassword string) (*Vault, error) {
	newMasterKey, err := crypto.NewKey(newMasterPassword, s.iterations)
	if err != nil {
		return nil, fmt.Errorf("failed to derive new master key: %w", err)
	}

	masterWrap, err := newMasterKey.Encrypt(s.vaultKey)
	if err != nil {
		newMasterKey.Destroy()
		return nil, fmt.Errorf("failed to wrap vault key with new master key: %w", err)
	}

	s.encrypted.MasterWrap = masterWrap
	s.encrypted.MasterSalt = newMasterKey.Salt()
	s.encrypted.Iterations = s.iterations
	s.encrypted.Version = crypto.CryptoVersion

	if err := SaveEncryptedVault(s.filePath, s.encrypted); err != nil {
		newMasterKey.Destroy()
		return nil, fmt.Errorf("failed to save vault after recovery: %w", err)
	}

	plaintext, err := crypto.DecryptWithKey(s.vaultKey, s.encrypted.VaultCiphertext)
	if err != nil {
		newMasterKey.Destroy()
		return nil, fmt.Errorf("failed to decrypt vault contents: %w", err)
	}
	defer crypto.SecureWipeBytes(plaintext)

	var data VaultData
	if err := json.Unmarshal(plaintext, &data); err != nil {
		newMasterKey.Destroy()
		return nil, fmt.Errorf("failed to parse vault data: %w", err)
	}

	vaultKeyCopy := append([]byte{}, s.vaultKey...)
	vault := &Vault{
		data:                  data,
		encrypted:             s.encrypted,
		masterKey:             newMasterKey,
		vaultKey:              vaultKeyCopy,
		filePath:              s.filePath,
		iterations:            s.iterations,
		pendingRecoveryPhrase: s.pendingPhrase,
	}

	crypto.SecureWipeBytes(s.vaultKey)
	return vault, nil
}

// ConsumePendingRecoveryPhrase returns the pending phrase once and clears it.
func (v *Vault) ConsumePendingRecoveryPhrase() string {
	v.mu.Lock()
	defer v.mu.Unlock()
	phrase := v.pendingRecoveryPhrase
	v.pendingRecoveryPhrase = ""
	return phrase
}

// Save persists the vault to disk using the master key to wrap the vault key.
func (v *Vault) Save() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.saveLocked()
}

// AddCredential adds a new credential to the vault.
func (v *Vault) AddCredential(cred Credential) error {
	if err := cred.Validate(); err != nil {
		return err
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	cred.ID = uuid.New().String()
	cred.Created = time.Now()
	cred.Modified = time.Now()
	v.data.Credentials = append(v.data.Credentials, cred)

	return v.saveLocked()
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
			return v.saveLocked()
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
			return v.saveLocked()
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

	q := strings.ToLower(query)
	var results []Credential

	for _, cred := range v.data.Credentials {
		if strings.Contains(strings.ToLower(cred.Site), q) ||
			strings.Contains(strings.ToLower(cred.Email), q) ||
			strings.Contains(strings.ToLower(cred.Username), q) {
			results = append(results, cred.Copy())
		}
	}

	return results
}

// ChangeMasterPassword changes the master password and re-wraps the vault key.
func (v *Vault) ChangeMasterPassword(newPassword string) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	newKey, err := crypto.NewKey(newPassword, v.iterations)
	if err != nil {
		return fmt.Errorf("failed to create new key: %w", err)
	}

	masterWrap, err := newKey.Encrypt(v.vaultKey)
	if err != nil {
		newKey.Destroy()
		return fmt.Errorf("failed to wrap vault key: %w", err)
	}

	v.encrypted.MasterWrap = masterWrap
	v.encrypted.MasterSalt = newKey.Salt()
	v.encrypted.Iterations = v.iterations

	if err := v.saveLocked(); err != nil {
		newKey.Destroy()
		return err
	}

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

	if len(v.vaultKey) > 0 {
		crypto.SecureWipeBytes(v.vaultKey)
		v.vaultKey = nil
	}

	for i := range v.data.Credentials {
		crypto.SecureWipeBytes([]byte(v.data.Credentials[i].Password))
	}
	v.data.Credentials = nil
}

// saveLocked assumes the caller holds v.mu.
func (v *Vault) saveLocked() error {
	jsonData, err := json.Marshal(v.data)
	if err != nil {
		return fmt.Errorf("failed to marshal vault data: %w", err)
	}
	defer crypto.SecureWipeBytes(jsonData)

	ciphertext, err := crypto.EncryptWithKey(v.vaultKey, jsonData)
	if err != nil {
		return fmt.Errorf("failed to encrypt vault data: %w", err)
	}
	v.encrypted.VaultCiphertext = ciphertext
	v.encrypted.Version = crypto.CryptoVersion
	v.encrypted.Iterations = v.iterations

	masterWrap, err := v.masterKey.Encrypt(v.vaultKey)
	if err != nil {
		return fmt.Errorf("failed to wrap vault key: %w", err)
	}
	v.encrypted.MasterWrap = masterWrap

	return SaveEncryptedVault(v.filePath, v.encrypted)
}

func openV2Vault(vaultPath string, encrypted *EncryptedVault, masterPassword string, fallbackIterations int) (*Vault, error) {
	iterations := encrypted.Iterations
	if iterations == 0 {
		iterations = fallbackIterations
	}

	masterKey, err := crypto.DeriveKey(masterPassword, encrypted.MasterSalt, iterations)
	if err != nil {
		return nil, fmt.Errorf("failed to derive master key: %w", err)
	}

	vaultKey, err := masterKey.Decrypt(encrypted.MasterWrap)
	if err != nil {
		masterKey.Destroy()
		return nil, errors.New("invalid master password")
	}

	plaintext, err := crypto.DecryptWithKey(vaultKey, encrypted.VaultCiphertext)
	if err != nil {
		masterKey.Destroy()
		crypto.SecureWipeBytes(vaultKey)
		return nil, errors.New("invalid master password")
	}
	defer crypto.SecureWipeBytes(plaintext)

	var data VaultData
	if err := json.Unmarshal(plaintext, &data); err != nil {
		masterKey.Destroy()
		crypto.SecureWipeBytes(vaultKey)
		return nil, fmt.Errorf("failed to parse vault data: %w", err)
	}

	vault := &Vault{
		data:       data,
		encrypted:  encrypted,
		masterKey:  masterKey,
		vaultKey:   vaultKey,
		filePath:   vaultPath,
		iterations: iterations,
	}

	return vault, nil
}

func migrateFromV1WithMaster(vaultPath string, encrypted *EncryptedVault, masterPassword string, iterations int) (*Vault, error) {
	masterKey, err := crypto.DeriveKey(masterPassword, encrypted.MasterSalt, iterations)
	if err != nil {
		return nil, fmt.Errorf("failed to derive legacy master key: %w", err)
	}

	plaintext, err := masterKey.Decrypt(encrypted.MasterData)
	if err != nil {
		masterKey.Destroy()
		return nil, errors.New("invalid master password")
	}
	defer crypto.SecureWipeBytes(plaintext)

	var data VaultData
	if err := json.Unmarshal(plaintext, &data); err != nil {
		masterKey.Destroy()
		return nil, fmt.Errorf("failed to parse legacy vault data: %w", err)
	}

	recoveryWords, err := crypto.GenerateRecoveryPhrase(0)
	if err != nil {
		masterKey.Destroy()
		return nil, fmt.Errorf("failed to generate recovery phrase: %w", err)
	}

	recoverySalt, err := crypto.GenerateRandomBytes(32)
	if err != nil {
		masterKey.Destroy()
		return nil, fmt.Errorf("failed to generate recovery salt: %w", err)
	}

	recoveryKey, err := crypto.DeriveRecoveryKey(recoveryWords, recoverySalt, iterations)
	if err != nil {
		masterKey.Destroy()
		return nil, fmt.Errorf("failed to derive recovery key: %w", err)
	}
	defer recoveryKey.Destroy()

	vaultKey, err := crypto.GenerateRandomBytes(32)
	if err != nil {
		masterKey.Destroy()
		return nil, fmt.Errorf("failed to generate vault key: %w", err)
	}

	vaultCiphertext, err := crypto.EncryptWithKey(vaultKey, plaintext)
	if err != nil {
		masterKey.Destroy()
		crypto.SecureWipeBytes(vaultKey)
		return nil, fmt.Errorf("failed to encrypt vault during migration: %w", err)
	}

	masterWrap, err := masterKey.Encrypt(vaultKey)
	if err != nil {
		masterKey.Destroy()
		crypto.SecureWipeBytes(vaultKey)
		return nil, fmt.Errorf("failed to wrap vault key during migration: %w", err)
	}

	recoveryWrap, err := recoveryKey.Encrypt(vaultKey)
	if err != nil {
		masterKey.Destroy()
		crypto.SecureWipeBytes(vaultKey)
		return nil, fmt.Errorf("failed to wrap recovery key during migration: %w", err)
	}

	updated := &EncryptedVault{
		Version:         crypto.CryptoVersion,
		Iterations:      iterations,
		MasterSalt:      masterKey.Salt(),
		RecoverySalt:    recoveryKey.Salt(),
		MasterWrap:      masterWrap,
		RecoveryWrap:    recoveryWrap,
		VaultCiphertext: vaultCiphertext,
	}

	if err := SaveEncryptedVault(vaultPath, updated); err != nil {
		masterKey.Destroy()
		crypto.SecureWipeBytes(vaultKey)
		return nil, fmt.Errorf("failed to save migrated vault: %w", err)
	}

	vault := &Vault{
		data:                  data,
		encrypted:             updated,
		masterKey:             masterKey,
		vaultKey:              vaultKey,
		filePath:              vaultPath,
		iterations:            iterations,
		pendingRecoveryPhrase: crypto.RecoveryPhraseString(recoveryWords),
	}

	return vault, nil
}

func beginRecoveryV2(vaultPath string, encrypted *EncryptedVault, phrase string, iterations int) (*RecoverySession, error) {
	if iterations == 0 {
		iterations = encrypted.Iterations
	}

	recoveryKey, err := crypto.DeriveRecoveryKeyFromPhrase(phrase, encrypted.RecoverySalt, iterations)
	if err != nil {
		return nil, ErrInvalidRecovery
	}
	defer recoveryKey.Destroy()

	vaultKey, err := recoveryKey.Decrypt(encrypted.RecoveryWrap)
	if err != nil {
		return nil, ErrInvalidRecovery
	}

	return &RecoverySession{
		encrypted:  encrypted,
		vaultKey:   vaultKey,
		filePath:   vaultPath,
		iterations: iterations,
	}, nil
}

func beginRecoveryV1(vaultPath string, encrypted *EncryptedVault, code string, iterations int) (*RecoverySession, error) {
	// Legacy recovery codes may not be word-based; derive directly.
	recoveryKey, err := crypto.DeriveKey(code, encrypted.RecoverySalt, iterations)
	if err != nil {
		return nil, ErrInvalidRecovery
	}
	defer recoveryKey.Destroy()

	plaintext, err := recoveryKey.Decrypt(encrypted.RecoveryData)
	if err != nil {
		return nil, ErrInvalidRecovery
	}
	defer crypto.SecureWipeBytes(plaintext)

	vaultKey, err := crypto.GenerateRandomBytes(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate vault key: %w", err)
	}

	vaultCiphertext, err := crypto.EncryptWithKey(vaultKey, plaintext)
	if err != nil {
		crypto.SecureWipeBytes(vaultKey)
		return nil, fmt.Errorf("failed to encrypt vault data: %w", err)
	}

	recoveryWords, err := crypto.GenerateRecoveryPhrase(0)
	if err != nil {
		crypto.SecureWipeBytes(vaultKey)
		return nil, fmt.Errorf("failed to generate new recovery phrase: %w", err)
	}

	recoverySalt, err := crypto.GenerateRandomBytes(32)
	if err != nil {
		crypto.SecureWipeBytes(vaultKey)
		return nil, fmt.Errorf("failed to generate recovery salt: %w", err)
	}

	newRecoveryKey, err := crypto.DeriveRecoveryKey(recoveryWords, recoverySalt, iterations)
	if err != nil {
		crypto.SecureWipeBytes(vaultKey)
		return nil, fmt.Errorf("failed to derive new recovery key: %w", err)
	}
	defer newRecoveryKey.Destroy()

	recoveryWrap, err := newRecoveryKey.Encrypt(vaultKey)
	if err != nil {
		crypto.SecureWipeBytes(vaultKey)
		return nil, fmt.Errorf("failed to wrap recovery key: %w", err)
	}

	migrated := &EncryptedVault{
		Version:         crypto.CryptoVersion,
		Iterations:      iterations,
		RecoverySalt:    newRecoveryKey.Salt(),
		RecoveryWrap:    recoveryWrap,
		VaultCiphertext: vaultCiphertext,
	}

	if err := SaveEncryptedVault(vaultPath, migrated); err != nil {
		crypto.SecureWipeBytes(vaultKey)
		return nil, fmt.Errorf("failed to save migrated recovery vault: %w", err)
	}

	return &RecoverySession{
		encrypted:     migrated,
		vaultKey:      vaultKey,
		filePath:      vaultPath,
		iterations:    iterations,
		pendingPhrase: crypto.RecoveryPhraseString(recoveryWords),
	}, nil
}
