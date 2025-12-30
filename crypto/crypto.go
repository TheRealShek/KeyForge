// Package crypto provides secure cryptographic operations for Keyforge.
// Uses AES-256-GCM for encryption and PBKDF2-SHA256 for key derivation.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

const (
	// CryptoVersion is the current vault format version
	CryptoVersion = 1

	keyLength   = 32 // AES-256
	saltLength  = 32
	nonceLength = 12 // GCM standard nonce size
)

var (
	ErrCiphertextTooShort = errors.New("ciphertext too short")
	ErrInvalidKeyLength   = errors.New("invalid key length")
	ErrInvalidSaltLength  = errors.New("invalid salt length")
)

// Key represents an opaque cryptographic key with its derivation salt.
// Keys must be explicitly destroyed after use to clear sensitive material.
type Key struct {
	key  []byte
	salt []byte
}

// GenerateRandomBytes generates cryptographically secure random bytes.
func GenerateRandomBytes(n int) ([]byte, error) {
	if n <= 0 {
		return nil, errors.New("invalid byte count")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return b, nil
}

// GenerateRecoveryCode generates a base64-encoded recovery code.
func GenerateRecoveryCode() (string, error) {
	bytes, err := GenerateRandomBytes(32)
	if err != nil {
		return "", fmt.Errorf("failed to generate recovery code: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// DeriveKey creates a Key from a password using PBKDF2-SHA256.
func DeriveKey(password string, salt []byte, iterations int) (*Key, error) {
	if password == "" {
		return nil, errors.New("password cannot be empty")
	}
	if len(salt) != saltLength {
		return nil, ErrInvalidSaltLength
	}
	if iterations < 100000 {
		return nil, errors.New("iteration count too low (minimum 100000)")
	}

	derivedKey := pbkdf2.Key([]byte(password), salt, iterations, keyLength, sha256.New)

	return &Key{
		key:  derivedKey,
		salt: append([]byte{}, salt...), // Copy salt
	}, nil
}

// NewKey creates a new Key with a random salt.
func NewKey(password string, iterations int) (*Key, error) {
	salt, err := GenerateRandomBytes(saltLength)
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	return DeriveKey(password, salt, iterations)
}

// Salt returns a copy of the key's salt.
func (k *Key) Salt() []byte {
	return append([]byte{}, k.salt...)
}

// Encrypt encrypts plaintext using AES-256-GCM.
func (k *Key) Encrypt(plaintext []byte) ([]byte, error) {
	if len(k.key) != keyLength {
		return nil, ErrInvalidKeyLength
	}

	block, err := aes.NewCipher(k.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce, err := GenerateRandomBytes(nonceLength)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Prepend nonce to ciphertext
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts ciphertext using AES-256-GCM.
func (k *Key) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(k.key) != keyLength {
		return nil, ErrInvalidKeyLength
	}

	if len(ciphertext) < nonceLength {
		return nil, ErrCiphertextTooShort
	}

	block, err := aes.NewCipher(k.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := ciphertext[:nonceLength]
	ciphertext = ciphertext[nonceLength:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// Destroy securely wipes the key from memory.
func (k *Key) Destroy() {
	secureWipe(k.key)
	secureWipe(k.salt)
}

// secureWipe overwrites sensitive data with zeros then random data.
func secureWipe(data []byte) {
	if len(data) == 0 {
		return
	}

	// Zero pass
	for i := range data {
		data[i] = 0
	}

	// Random pass (best effort - ignore errors since memory is already zeroed)
	io.ReadFull(rand.Reader, data)
}

// SecureWipeBytes is a public wrapper for secureWipe.
func SecureWipeBytes(data []byte) {
	secureWipe(data)
}

// ConstantTimeCompare performs constant-time comparison of two byte slices.
// Returns true if they are equal, false otherwise.
func ConstantTimeCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
