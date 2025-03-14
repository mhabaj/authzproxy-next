// internal/auth/types.go
package auth

import (
	"net/http"
)

// Identity represents an authenticated identity
type Identity struct {
	// Subject is the unique identifier for this identity
	Subject string

	// Provider is the authentication provider (e.g., "mtls", "oidc", "bearer")
	Provider string

	// Attributes contains additional identity information
	Attributes map[string]interface{}
}

// Authenticator defines the interface for authentication methods
type Authenticator interface {
	// Name returns the name of this authenticator
	Name() string

	// GetMiddleware returns an http.Handler middleware that performs authentication
	GetMiddleware(next http.Handler) http.Handler
}
