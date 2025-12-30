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
	"math/big"
	"strings"

	"github.com/tyler-smith/go-bip39/wordlists"
	"golang.org/x/crypto/pbkdf2"
)

const (
	// CryptoVersion is the current vault format version
	CryptoVersion = 2

	keyLength   = 32 // AES-256
	saltLength  = 32
	nonceLength = 12 // GCM standard nonce size

	defaultRecoveryWordCount = 12
	minRecoveryWords         = 12
	maxRecoveryWords         = 16
)

var (
	ErrCiphertextTooShort      = errors.New("ciphertext too short")
	ErrInvalidKeyLength        = errors.New("invalid key length")
	ErrInvalidSaltLength       = errors.New("invalid salt length")
	ErrInvalidRecoveryWord     = errors.New("invalid recovery word")
	ErrInvalidRecoveryWordCount = errors.New("invalid recovery word count")
	ErrInvalidRawKeyLength     = errors.New("invalid raw key length")
)

var (
	recoveryWordList  = wordlists.English
	recoveryWordIndex map[string]int
)

func init() {
	recoveryWordIndex = make(map[string]int, len(recoveryWordList))
	for i, w := range recoveryWordList {
		recoveryWordIndex[w] = i
	}
	if len(recoveryWordIndex) == 0 {
		panic("recovery wordlist not initialized")
	}
}

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

// GenerateRecoveryCode generates a base64-encoded recovery code (legacy helper).
func GenerateRecoveryCode() (string, error) {
	bytes, err := GenerateRandomBytes(32)
	if err != nil {
		return "", fmt.Errorf("failed to generate recovery code: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// GenerateRecoveryPhrase returns a uniformly random list of recovery words.
func GenerateRecoveryPhrase(wordCount int) ([]string, error) {
	if wordCount == 0 {
		wordCount = defaultRecoveryWordCount
	}
	if wordCount < minRecoveryWords || wordCount > maxRecoveryWords {
		return nil, ErrInvalidRecoveryWordCount
	}

	words := make([]string, wordCount)
	max := big.NewInt(int64(len(recoveryWordList)))
	for i := 0; i < wordCount; i++ {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			return nil, fmt.Errorf("failed to generate recovery word %d: %w", i, err)
		}
		words[i] = recoveryWordList[idx.Int64()]
	}

	return words, nil
}

// NormalizeRecoveryPhrase lowercases, trims, and validates a recovery phrase.
func NormalizeRecoveryPhrase(phrase string) ([]string, error) {
	words := strings.Fields(strings.ToLower(strings.TrimSpace(phrase)))
	if len(words) < minRecoveryWords || len(words) > maxRecoveryWords {
		return nil, ErrInvalidRecoveryWordCount
	}

	for _, w := range words {
		if _, ok := recoveryWordIndex[w]; !ok {
			return nil, fmt.Errorf("%w: %s", ErrInvalidRecoveryWord, w)
		}
	}

	return words, nil
}

// RecoveryPhraseString joins words into a single space-separated phrase.
func RecoveryPhraseString(words []string) string {
	return strings.Join(words, " ")
}

// DeriveRecoveryKey derives a key from a validated recovery word list.
func DeriveRecoveryKey(words []string, salt []byte, iterations int) (*Key, error) {
	return DeriveKey(RecoveryPhraseString(words), salt, iterations)
}

// DeriveRecoveryKeyFromPhrase derives a key from a free-form phrase string.
func DeriveRecoveryKeyFromPhrase(phrase string, salt []byte, iterations int) (*Key, error) {
	words, err := NormalizeRecoveryPhrase(phrase)
	if err != nil {
		return nil, err
	}
	return DeriveRecoveryKey(words, salt, iterations)
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

	return EncryptWithKey(k.key, plaintext)
}

// Decrypt decrypts ciphertext using AES-256-GCM.
func (k *Key) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(k.key) != keyLength {
		return nil, ErrInvalidKeyLength
	}

	return DecryptWithKey(k.key, ciphertext)
}

// EncryptWithKey encrypts plaintext using a raw 32-byte key.
func EncryptWithKey(rawKey []byte, plaintext []byte) ([]byte, error) {
	if len(rawKey) != keyLength {
		return nil, ErrInvalidRawKeyLength
	}

	block, err := aes.NewCipher(rawKey)
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

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// DecryptWithKey decrypts ciphertext using a raw 32-byte key.
func DecryptWithKey(rawKey []byte, ciphertext []byte) ([]byte, error) {
	if len(rawKey) != keyLength {
		return nil, ErrInvalidRawKeyLength
	}

	if len(ciphertext) < nonceLength {
		return nil, ErrCiphertextTooShort
	}

	block, err := aes.NewCipher(rawKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := ciphertext[:nonceLength]
	ct := ciphertext[nonceLength:]

	plaintext, err := gcm.Open(nil, nonce, ct, nil)
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

	for i := range data {
		data[i] = 0
	}

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
