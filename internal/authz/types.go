// internal/authz/types.go
package authz

import (
	"context"
	"net/http"

	"authzproxy/internal/auth"
)

// Decision represents an authorization decision
type Decision int

const (
	// Allow indicates the request is allowed
	Allow Decision = iota
	// Deny indicates the request is denied
	Deny
	// Unauthorized indicates the request is unauthorized (no identity)
	Unauthorized
	// Error indicates an error occurred during authorization
	Error
)

// Request represents an authorization request
type Request struct {
	// Identity is the identity to authorize
	Identity *auth.Identity

	// Resource is the resource being accessed
	Resource string

	// Permission is the permission being checked
	Permission string

	// Context is the request context
	Context context.Context
}

// Response represents an authorization response
type Response struct {
	// Decision is the authorization decision
	Decision Decision

	// Reason provides additional information about the decision
	Reason string

	// Error is set if an error occurred during authorization
	Error error
}

// Authorizer defines the interface for authorization
type Authorizer interface {
	// Authorize checks if the identity has the specified permission on the resource
	Authorize(req *Request) *Response

	// Middleware creates an HTTP middleware for authorization
	Middleware(permission string) func(http.Handler) http.Handler
}
