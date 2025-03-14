// internal/auth/context.go
package auth

import (
	"context"
)

// ContextKey is a type-safe key for context values
type ContextKey string

const (
	// IdentityContextKey is the key used to store the identity in the context
	IdentityContextKey ContextKey = "auth:identity"

	// AuthTypeContextKey is the key used to store the authentication type
	AuthTypeContextKey ContextKey = "auth:type"
)

// AuthType represents the type of authentication used
type AuthType string

const (
	// AuthTypeMTLS represents mTLS authentication
	AuthTypeMTLS AuthType = "mtls"

	// AuthTypeOIDC represents OIDC authentication
	AuthTypeOIDC AuthType = "oidc"

	// AuthTypeBearer represents Bearer token authentication
	AuthTypeBearer AuthType = "bearer"
)

// IdentityFromContext extracts the identity from the request context
func IdentityFromContext(ctx context.Context) *Identity {
	if identity, ok := ctx.Value(IdentityContextKey).(*Identity); ok {
		return identity
	}
	return nil
}

// ContextWithIdentity adds an identity to a context
func ContextWithIdentity(ctx context.Context, identity *Identity) context.Context {
	return context.WithValue(ctx, IdentityContextKey, identity)
}

// AuthTypeFromContext extracts the authentication type from the context
func AuthTypeFromContext(ctx context.Context) AuthType {
	if authType, ok := ctx.Value(AuthTypeContextKey).(AuthType); ok {
		return authType
	}
	return ""
}

// ContextWithAuthType adds an authentication type to a context
func ContextWithAuthType(ctx context.Context, authType AuthType) context.Context {
	return context.WithValue(ctx, AuthTypeContextKey, authType)
}
