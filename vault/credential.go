// Package vault provides secure credential storage with encryption.
package vault

import (
	"time"
)

// Credential represents a stored password with metadata.
type Credential struct {
	ID       string    `json:"id"`
	Site     string    `json:"site"`
	Password string    `json:"password"`
	Email    string    `json:"email,omitempty"`
	Username string    `json:"username,omitempty"`
	Created  time.Time `json:"created"`
	Modified time.Time `json:"modified"`
}

// Copy returns a deep copy of the credential.
func (c Credential) Copy() Credential {
	return Credential{
		ID:       c.ID,
		Site:     c.Site,
		Password: c.Password,
		Email:    c.Email,
		Username: c.Username,
		Created:  c.Created,
		Modified: c.Modified,
	}
}

// Validate checks if the credential has required fields.
func (c Credential) Validate() error {
	if c.Site == "" {
		return ErrSiteRequired
	}
	if c.Password == "" {
		return ErrPasswordRequired
	}
	if c.Email == "" && c.Username == "" {
		return ErrIdentityRequired
	}
	return nil
}

// Identity returns the email or username for display.
func (c Credential) Identity() string {
	if c.Email != "" {
		return c.Email
	}
	return c.Username
}
