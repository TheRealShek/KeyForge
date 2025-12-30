package vault

import (
"os"
"testing"
"time"
)

func TestCreateAndOpenVault(t *testing.T) {
// Use temp file for testing
tmpFile := os.TempDir() + "/test-vault-" + time.Now().Format("20060102150405") + ".vault"
defer os.Remove(tmpFile)

// Override vault path for testing
originalPath := os.Getenv("HOME")
defer func() {
if originalPath != "" {
os.Setenv("HOME", originalPath)
}
}()

password := "test-password-123"
iterations := 100000

vault, recoveryCode, err := CreateVault(password, iterations)
if err != nil {
t.Fatalf("CreateVault() error = %v", err)
}
defer vault.Close()

if recoveryCode == "" {
t.Error("CreateVault() recovery code should not be empty")
}

// Test opening with master password
vault2, err := OpenVault(password, false, iterations)
if err != nil {
t.Fatalf("OpenVault() with password error = %v", err)
}
defer vault2.Close()

// Test opening with recovery code
vault3, err := OpenVault(recoveryCode, true, iterations)
if err != nil {
t.Fatalf("OpenVault() with recovery code error = %v", err)
}
defer vault3.Close()
}

func TestAddAndGetCredential(t *testing.T) {
password := "test-password"
vault, _, err := CreateVault(password, 100000)
if err != nil {
t.Fatalf("CreateVault() error = %v", err)
}
defer vault.Close()

cred := Credential{
Site:     "example.com",
Email:    "user@example.com",
Password: "secret123",
}

if err := vault.AddCredential(cred); err != nil {
t.Fatalf("AddCredential() error = %v", err)
}

creds := vault.GetAllCredentials()
if len(creds) != 1 {
t.Errorf("GetAllCredentials() count = %d, want 1", len(creds))
}
if creds[0].Site != "example.com" {
t.Errorf("GetAllCredentials() site = %s, want example.com", creds[0].Site)
}
}

func TestUpdateCredential(t *testing.T) {
vault, _, _ := CreateVault("password", 100000)
defer vault.Close()

cred := Credential{
Site:     "example.com",
Email:    "user@example.com",
Password: "old-password",
}
vault.AddCredential(cred)

creds := vault.GetAllCredentials()
id := creds[0].ID

updated := Credential{
Site:     "example.com",
Email:    "user@example.com",
Password: "new-password",
}

if err := vault.UpdateCredential(id, updated); err != nil {
t.Fatalf("UpdateCredential() error = %v", err)
}

result, _ := vault.GetCredential(id)
if result.Password != "new-password" {
t.Errorf("UpdateCredential() password = %s, want new-password", result.Password)
}
}

func TestDeleteCredential(t *testing.T) {
vault, _, _ := CreateVault("password", 100000)
defer vault.Close()

cred := Credential{
Site:     "example.com",
Email:    "user@example.com",
Password: "secret",
}
vault.AddCredential(cred)

creds := vault.GetAllCredentials()
id := creds[0].ID

if err := vault.DeleteCredential(id); err != nil {
t.Fatalf("DeleteCredential() error = %v", err)
}

creds = vault.GetAllCredentials()
if len(creds) != 0 {
t.Errorf("DeleteCredential() count = %d, want 0", len(creds))
}
}

func TestSearchCredentials(t *testing.T) {
vault, _, _ := CreateVault("password", 100000)
defer vault.Close()

vault.AddCredential(Credential{Site: "github.com", Email: "user@example.com", Password: "pass1"})
vault.AddCredential(Credential{Site: "gitlab.com", Email: "user@example.com", Password: "pass2"})
vault.AddCredential(Credential{Site: "example.com", Username: "admin", Password: "pass3"})

results := vault.SearchCredentials("git")
if len(results) != 2 {
t.Errorf("SearchCredentials('git') count = %d, want 2", len(results))
}

results = vault.SearchCredentials("admin")
if len(results) != 1 {
t.Errorf("SearchCredentials('admin') count = %d, want 1", len(results))
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
