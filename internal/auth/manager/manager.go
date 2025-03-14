// internal/auth/manager/manager.go
package manager

import (
	"fmt"
	"net/http"

	"authzproxy/internal/auth"
	"authzproxy/internal/auth/bearer"
	"authzproxy/internal/auth/mtls"
	"authzproxy/internal/auth/oidc"
	"authzproxy/internal/config"
	"authzproxy/internal/observability/logging"
	"authzproxy/internal/observability/metrics"
	"authzproxy/internal/tls"
)

// Manager coordinates multiple authentication methods
type Manager struct {
	logger         *logging.Logger
	authenticators []auth.Authenticator
}

// NewManager creates a new authentication manager
func NewManager(authenticators []auth.Authenticator, logger *logging.Logger) *Manager {
	return &Manager{
		authenticators: authenticators,
		logger:         logger.WithModule("auth.manager"),
	}
}

// Middleware creates a middleware chain from all enabled authenticators
func (m *Manager) Middleware(next http.Handler) http.Handler {
	// Apply authenticators in the correct order (not in reverse)
	// This ensures that mTLS is checked first, then Bearer, then OIDC
	handler := next
	for _, authenticator := range m.authenticators {
		handler = authenticator.GetMiddleware(handler)
		m.logger.Debug("Added authenticator to middleware chain", "authenticator", authenticator.Name())
	}
	return handler
}

// GetAuthenticators returns the list of enabled authenticators
func (m *Manager) GetAuthenticators() []auth.Authenticator {
	return m.authenticators
}

// NewManagerFromConfig creates a Manager with authenticators configured from application config
func NewManagerFromConfig(cfg *config.Config, tlsConfig *tls.Config, logger *logging.Logger, metrics *metrics.Collector) (*Manager, error) {
	logger = logger.WithModule("auth.factory")
	var authenticators []auth.Authenticator

	// Initialize authenticators based on configuration - order matters!
	// mTLS should be first, then Bearer, then OIDC

	// mTLS authenticator
	if cfg.Auth.MTLS.Enabled {
		mtlsAuth, err := mtls.New(mtls.Config{
			Enabled:   true,
			CAPaths:   cfg.Auth.MTLS.CAPaths,
			TLSConfig: tlsConfig, // Pass the TLS config to ensure matching CA pools
		}, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize mTLS authenticator: %w", err)
		}
		authenticators = append(authenticators, mtlsAuth)
		logger.Info("mTLS authentication enabled")
	}

	// Bearer authenticator
	if cfg.Auth.Bearer.Enabled {
		bearerAuth, err := bearer.New(bearer.Config{
			Enabled:  true,
			Issuer:   cfg.Auth.Bearer.Issuer,
			ClientID: cfg.Auth.Bearer.ClientID,
		}, logger, metrics)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize Bearer authenticator: %w", err)
		}
		authenticators = append(authenticators, bearerAuth)
		logger.Info("Bearer authentication enabled")
	}

	// OIDC authenticator (last in chain)
	if cfg.Auth.OIDC.Enabled {
		oidcAuth, err := oidc.New(oidc.Config{
			Enabled:      true,
			Issuer:       cfg.Auth.OIDC.Issuer,
			ClientID:     cfg.Auth.OIDC.ClientID,
			ClientSecret: cfg.Auth.OIDC.ClientSecret,
			RedirectURL:  cfg.Auth.OIDC.RedirectURL,
			Scopes:       cfg.Auth.OIDC.Scopes,
			CookieName:   cfg.Auth.OIDC.CookieName,
			CookieSecret: cfg.Auth.OIDC.CookieSecret,
		}, logger, metrics)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize OIDC authenticator: %w", err)
		}
		authenticators = append(authenticators, oidcAuth)
		logger.Info("OIDC authentication enabled")
	}

	if len(authenticators) == 0 {
		logger.Warn("No authentication methods enabled")
	}

	return NewManager(authenticators, logger), nil
}
