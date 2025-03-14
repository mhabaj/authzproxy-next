// internal/config/types.go
package config

import (
	"net/url"
	"time"
)

// Config represents the complete application configuration
type Config struct {
	// Server holds HTTP server configuration
	Server struct {
		// Address is the address to listen on
		Address string
		// ShutdownTimeout is the maximum time to wait for a graceful shutdown
		ShutdownTimeout time.Duration
	}

	// Metrics holds metrics server configuration
	Metrics struct {
		// Address is the address to listen on for the metrics server
		Address string
	}

	// TLS holds TLS configuration
	TLS struct {
		// Enabled indicates whether TLS is enabled
		Enabled bool
		// CertPath is the path to the TLS certificate
		CertPath string
		// KeyPath is the path to the TLS key
		KeyPath string
		// CAPath is the path to the CA certificate for client verification
		CAPath string
	}

	// Upstream holds configuration for the upstream service
	Upstream struct {
		// URL is the URL of the upstream service
		URL *url.URL
		// Timeout is the maximum time to wait for upstream responses
		Timeout time.Duration
	}

	// Auth holds authentication configuration
	Auth struct {
		// MTLS holds mTLS authentication configuration
		MTLS struct {
			// Enabled indicates whether mTLS authentication is enabled
			Enabled bool
			// CAPaths is a list of paths to CA certificates for client verification
			CAPaths []string
		}

		// OIDC holds OIDC authentication configuration
		OIDC struct {
			// Enabled indicates whether OIDC authentication is enabled
			Enabled bool
			// Issuer is the OIDC issuer URL
			Issuer string
			// ClientID is the OIDC client ID
			ClientID string
			// ClientSecret is the OIDC client secret
			ClientSecret string
			// RedirectURL is the redirect URL for OIDC authentication
			RedirectURL string
			// Scopes is a list of OIDC scopes to request
			Scopes []string
			// CookieName is the name of the session cookie
			CookieName string
			// CookieSecret is the secret key for cookie encryption
			CookieSecret string
		}

		// Bearer holds Bearer token authentication configuration
		Bearer struct {
			// Enabled indicates whether Bearer token authentication is enabled
			Enabled bool
			// Issuer is the JWT issuer URL
			Issuer string
			// ClientID is the client ID for token validation
			ClientID string
		}
	}

	// Authz holds authorization configuration
	Authz struct {
		// Type is the type of authorizer to use (spicedb, simple)
		Type string

		// SpiceDB holds SpiceDB configuration
		SpiceDB struct {
			// Endpoint is the SpiceDB endpoint
			Endpoint string
			// Insecure indicates whether to use an insecure connection
			Insecure bool
			// Token is the SpiceDB authentication token
			Token string
			// ResourceType is the SpiceDB resource type
			ResourceType string
			// ResourceID is the SpiceDB resource ID
			ResourceID string
			// SubjectType is the SpiceDB subject type
			SubjectType string
		}
	}

	// Observability holds observability configuration
	Observability struct {
		// LogLevel is the minimum log level to emit
		LogLevel string
		// LogFormat is the log format (json, text, console)
		LogFormat string
	}

	// Rules holds route rules configuration
	Rules []Rule
}

// Rule defines a routing rule for the proxy
type Rule struct {
	// Name is a unique identifier for the rule
	Name string `json:"name" yaml:"name"`

	// Action determines what action to take for matched requests
	// Can be "allow", "deny", or "auth"
	Action string `json:"action" yaml:"action"`

	// Paths is a list of URL paths this rule applies to
	Paths []string `json:"paths" yaml:"paths"`

	// MatchPrefix indicates whether to match the path prefix instead of exact match
	MatchPrefix bool `json:"match_prefix" yaml:"match_prefix"`

	// Methods is a list of HTTP methods this rule applies to (empty = all methods)
	Methods []string `json:"methods" yaml:"methods"`

	// Permission is the permission required for "auth" action
	// Ignored for other actions
	Permission string `json:"permission" yaml:"permission"`

	// Resource is the resource identifier for authorization checks
	// If empty, the default resource from configuration is used
	Resource string `json:"resource" yaml:"resource"`
}
