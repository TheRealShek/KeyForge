package vault

import (
	"os"
	"strings"
	"testing"
)

func withTempHome(t *testing.T) func() {
	t.Helper()
	old := os.Getenv("HOME")
	temp := t.TempDir()
	if err := os.Setenv("HOME", temp); err != nil {
		t.Fatalf("failed to set HOME: %v", err)
	}
	return func() {
		os.Setenv("HOME", old)
	}
}

func TestHappyPathMasterLogin(t *testing.T) {
	restore := withTempHome(t)
	defer restore()

	password := "test-password-123"
	iterations := 150000

	v, phrase, err := CreateVault(password, iterations)
	if err != nil {
		t.Fatalf("CreateVault() error = %v", err)
	}
	if phrase == "" {
		t.Fatal("expected recovery phrase")
	}
	if err := v.AddCredential(Credential{Site: "example.com", Email: "user@example.com", Password: "secret123"}); err != nil {
		t.Fatalf("AddCredential() error = %v", err)
	}
	v.Close()

	reopened, err := OpenVault(password, iterations)
	if err != nil {
		t.Fatalf("OpenVault() error = %v", err)
	}
	defer reopened.Close()
	creds := reopened.GetAllCredentials()
	if len(creds) != 1 {
		t.Fatalf("unexpected credential count = %d", len(creds))
	}
}

func TestRecoveryResetFlow(t *testing.T) {
	restore := withTempHome(t)
	defer restore()

	iterations := 150000
	master := "master-one"
	newMaster := "master-two"

	v, phrase, err := CreateVault(master, iterations)
	if err != nil {
		t.Fatalf("CreateVault() error = %v", err)
	}
	if err := v.AddCredential(Credential{Site: "git.example", Email: "me@example.com", Password: "pw"}); err != nil {
		t.Fatalf("AddCredential() error = %v", err)
	}
	v.Close()

	session, err := BeginRecovery(phrase, iterations)
	if err != nil {
		t.Fatalf("BeginRecovery() error = %v", err)
	}

	recovered, err := session.Complete(newMaster)
	if err != nil {
		t.Fatalf("Complete() error = %v", err)
	}
	recovered.Close()

	if _, err := OpenVault(master, iterations); err == nil {
		t.Fatal("old master password should fail after recovery reset")
	}

	reopened, err := OpenVault(newMaster, iterations)
	if err != nil {
		t.Fatalf("OpenVault() with new master failed: %v", err)
	}
	defer reopened.Close()
	creds := reopened.GetAllCredentials()
	if len(creds) != 1 || creds[0].Site != "git.example" {
		t.Fatalf("credentials not preserved across recovery reset")
	}
}

func TestRecoveryDoesNotGrantDirectAccess(t *testing.T) {
	restore := withTempHome(t)
	defer restore()

	iterations := 130000
	password := "master-pass"

	_, phrase, err := CreateVault(password, iterations)
	if err != nil {
		t.Fatalf("CreateVault() error = %v", err)
	}

	if _, err := OpenVault(phrase, iterations); err == nil {
		t.Fatal("recovery phrase must not unlock vault without reset")
	}

	session, err := BeginRecovery(phrase, iterations)
	if err != nil {
		t.Fatalf("BeginRecovery() error = %v", err)
	}
	// Do not call Complete; ensure vault remains locked for master login.
	if _, err := OpenVault(password, iterations); err != nil {
		t.Fatalf("master password should still work before recovery completion: %v", err)
	}
	_ = session
}

func TestRecoveryPhraseNotPersistedInVaultFile(t *testing.T) {
	restore := withTempHome(t)
	defer restore()

	password := "master-pass"
	iterations := 120000

	_, phrase, err := CreateVault(password, iterations)
	if err != nil {
		t.Fatalf("CreateVault() error = %v", err)
	}

	vaultPath, err := GetVaultPath()
	if err != nil {
		t.Fatalf("GetVaultPath() error = %v", err)
	}

	contents, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatalf("failed to read vault file: %v", err)
	}

	if strings.Contains(string(contents), strings.Fields(phrase)[0]) {
		t.Fatalf("vault file unexpectedly contains recovery material")
	}
}

func TestCredentialValidation(t *testing.T) {
	tests := []struct {
		name    string
		cred    Credential
		wantErr error
	}{
		{
			"valid with email",
			Credential{Site: "example.com", Email: "user@example.com", Password: "pass"},
			nil,
		},
		{
			"valid with username",
			Credential{Site: "example.com", Username: "user", Password: "pass"},
			nil,
		},
		{
			"missing site",
			Credential{Email: "user@example.com", Password: "pass"},
			ErrSiteRequired,
		},
		{
			"missing password",
			Credential{Site: "example.com", Email: "user@example.com"},
			ErrPasswordRequired,
		},
		{
			"missing identity",
			Credential{Site: "example.com", Password: "pass"},
			ErrIdentityRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cred.Validate()
			if err != tt.wantErr {
				t.Errorf("Validate() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}
