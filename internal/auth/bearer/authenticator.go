// internal/auth/bearer/authenticator.go
package bearer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"authzproxy/internal/auth"
	"authzproxy/internal/contextutil"
	"authzproxy/internal/observability/logging"
	"authzproxy/internal/observability/metrics"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/exp/slices"
)

// Authenticator implements Bearer token authentication
type Authenticator struct {
	logger   *logging.Logger
	metrics  *metrics.Collector
	enabled  bool
	verifier *oidc.IDTokenVerifier
	clientID string
	appCtx   context.Context
}

// Config holds Bearer authenticator configuration
type Config struct {
	// Enabled indicates whether Bearer authentication is enabled
	Enabled bool

	// Issuer is the token issuer URL
	Issuer string

	// ClientID is the client ID for token validation
	ClientID string
}

// audiences helps unmarshall the audience claim which can be either a string or an array
type audiences []string

func (a *audiences) UnmarshalJSON(data []byte) error {
	// Try as a single string
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = []string{single}
		return nil
	}

	// Try as an array of strings
	var multiple []string
	if err := json.Unmarshal(data, &multiple); err == nil {
		*a = multiple
		return nil
	}

	return fmt.Errorf("invalid audience claim format")
}

// New creates a new Bearer authenticator
func New(config Config, logger *logging.Logger, metrics *metrics.Collector) (*Authenticator, error) {
	logger = logger.WithModule("auth.bearer")

	if !config.Enabled {
		return &Authenticator{
			logger:  logger,
			metrics: metrics,
			enabled: false,
		}, nil
	}

	// Basic validation
	if config.Issuer == "" {
		return nil, fmt.Errorf("Bearer authentication enabled but no issuer provided")
	}

	if config.ClientID == "" {
		return nil, fmt.Errorf("Bearer authentication enabled but no client ID provided")
	}

	// Create context for OIDC operations
	ctx := context.Background()

	// Initialize OIDC provider
	logger.Debug("Initializing OIDC provider for Bearer authentication", "issuer", config.Issuer)
	provider, err := oidc.NewProvider(ctx, config.Issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize OIDC provider for Bearer: %w", err)
	}

	// Create OIDC config
	oidcConfig := &oidc.Config{
		ClientID:          config.ClientID,
		SkipClientIDCheck: true, // We do our own checks for better error reporting
	}

	// Create authenticator
	auth := &Authenticator{
		logger:   logger,
		metrics:  metrics,
		enabled:  true,
		verifier: provider.Verifier(oidcConfig),
		clientID: config.ClientID,
		appCtx:   ctx,
	}

	return auth, nil
}

// Name returns the name of this authenticator
func (a *Authenticator) Name() string {
	return "bearer"
}

// GetMiddleware returns an http.Handler middleware that performs Bearer authentication
func (a *Authenticator) GetMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.enabled {
			next.ServeHTTP(w, r)
			return
		}

		// Get the logger from the request context
		ctx := r.Context()
		logger := logging.LoggerFromContext(ctx)
		if logger == nil {
			logger = a.logger
		}

		// Check if we already have an identity in the context
		if identity := contextutil.GetIdentity(ctx); identity != nil {
			logger.Debug("Skipping Bearer: identity already set", "subject", identity.Subject)
			next.ServeHTTP(w, r)
			return
		}

		// Check if we have a Bearer token
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			// No Bearer token, pass to next middleware
			logger.Debug("No Bearer token found, passing to next middleware")
			next.ServeHTTP(w, r)
			return
		}

		// Extract the token - if client presented a Bearer token, we must validate it
		// If validation fails, do not fall back to other methods
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenStr == "" {
			logger.Debug("Empty Bearer token, passing to next middleware")
			next.ServeHTTP(w, r)
			return
		}

		logger.Debug("Bearer token found, verifying...")

		// Verify the token
		idToken, err := a.verifier.Verify(a.appCtx, tokenStr)
		if err != nil {
			logger.Error("Bearer token verification failed", logging.Err(err))
			a.metrics.RecordAuthentication("bearer", false)
			// Important: Return status 403 as in original code
			http.Error(w, "Invalid Bearer token", http.StatusForbidden)
			return // Must return to prevent passing to next auth method
		}

		// Extract claims from the token - use audiences type for proper handling
		var claims struct {
			Subject string    `json:"sub"`
			Azp     string    `json:"azp,omitempty"`
			Aud     audiences `json:"aud,omitempty"`
			Scope   string    `json:"scope,omitempty"`
		}

		if err := idToken.Claims(&claims); err != nil {
			logger.Error("Failed to parse claims from Bearer token", logging.Err(err))
			a.metrics.RecordAuthentication("bearer", false)
			http.Error(w, "Failed to parse token claims", http.StatusForbidden)
			return
		}

		// Check if the audience or azp matches the client ID - using slices.Contains for arrays
		if claims.Azp != a.clientID && !slices.Contains(claims.Aud, a.clientID) {
			logger.Error("Bearer token audience mismatch",
				"expectedClientID", a.clientID,
				"aud", claims.Aud,
				"azp", claims.Azp,
			)
			a.metrics.RecordAuthentication("bearer", false)
			http.Error(w, "Invalid Bearer token audience", http.StatusForbidden)
			return
		}

		// Create identity
		identity := &auth.Identity{
			Subject:  claims.Subject,
			Provider: a.Name(),
			Attributes: map[string]interface{}{
				"token": tokenStr,
			},
		}

		logger.Debug("Bearer token valid", "subject", claims.Subject, "path", r.URL.Path)
		a.metrics.RecordAuthentication("bearer", true)

		// Add identity and auth type to request context
		ctx = contextutil.WithIdentity(ctx, identity)
		ctx = contextutil.WithAuthType(ctx, auth.AuthTypeBearer)

		// Continue with the next handler
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
