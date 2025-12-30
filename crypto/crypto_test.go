package crypto

import (
	"bytes"
	"strings"
	"testing"
)

func TestGenerateRandomBytes(t *testing.T) {
	tests := []struct {
		name    string
		n       int
		wantErr bool
	}{
		{"valid length", 32, false},
		{"zero length", 0, true},
		{"negative length", -1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GenerateRandomBytes(tt.n)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateRandomBytes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && len(got) != tt.n {
				t.Errorf("GenerateRandomBytes() length = %v, want %v", len(got), tt.n)
			}
		})
	}
}

func TestEncryptDecrypt(t *testing.T) {
	password := "test-password-123"
	plaintext := []byte("sensitive data here")

	key, err := NewKey(password, 100000)
	if err != nil {
		t.Fatalf("NewKey() error = %v", err)
	}
	defer key.Destroy()

	ciphertext, err := key.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	decrypted, err := key.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypt() = %v, want %v", decrypted, plaintext)
	}
}

func TestDeriveKey(t *testing.T) {
	password := "test-password"
	salt := make([]byte, 32)

	key1, err := DeriveKey(password, salt, 100000)
	if err != nil {
		t.Fatalf("DeriveKey() error = %v", err)
	}
	defer key1.Destroy()

	key2, err := DeriveKey(password, salt, 100000)
	if err != nil {
		t.Fatalf("DeriveKey() error = %v", err)
	}
	defer key2.Destroy()

	if !bytes.Equal(key1.key, key2.key) {
		t.Error("DeriveKey() should produce same key for same inputs")
	}
}

func TestConstantTimeCompare(t *testing.T) {
	a := []byte("secret")
	b := []byte("secret")
	c := []byte("different")

	if !ConstantTimeCompare(a, b) {
		t.Error("ConstantTimeCompare() should return true for equal slices")
	}

	if ConstantTimeCompare(a, c) {
		t.Error("ConstantTimeCompare() should return false for different slices")
	}
}

func TestDecryptInvalidCiphertext(t *testing.T) {
	key, _ := NewKey("password", 100000)
	defer key.Destroy()

	if _, err := key.Decrypt([]byte("short")); err == nil {
		t.Error("Decrypt() should fail on short ciphertext")
	}

	if _, err := key.Decrypt([]byte("this is not encrypted data at all")); err == nil {
		t.Error("Decrypt() should fail on invalid ciphertext")
	}
}

func TestGenerateRecoveryPhrase(t *testing.T) {
	words, err := GenerateRecoveryPhrase(12)
	if err != nil {
		t.Fatalf("GenerateRecoveryPhrase() error = %v", err)
	}
	if len(words) != 12 {
		t.Fatalf("expected 12 words, got %d", len(words))
	}
	phrase := RecoveryPhraseString(words)
	normalized, err := NormalizeRecoveryPhrase(phrase)
	if err != nil {
		t.Fatalf("NormalizeRecoveryPhrase() error = %v", err)
	}
	if len(normalized) != 12 {
		t.Fatalf("normalize length mismatch: %d", len(normalized))
	}
	if strings.ToLower(phrase) != phrase {
		t.Fatal("phrase should already be lowercase")
	}
}

func TestEncryptWithKeyHelpers(t *testing.T) {
	raw := bytes.Repeat([]byte{0x42}, 32)
	ct, err := EncryptWithKey(raw, []byte("hello"))
	if err != nil {
		t.Fatalf("EncryptWithKey() error = %v", err)
	}
	pt, err := DecryptWithKey(raw, ct)
	if err != nil {
		t.Fatalf("DecryptWithKey() error = %v", err)
	}
	if string(pt) != "hello" {
		t.Fatalf("unexpected plaintext: %s", pt)
	}
}
