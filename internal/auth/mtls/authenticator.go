// internal/auth/mtls/authenticator.go
package mtls

import (
	"crypto/x509"
	"fmt"
	"net/http"
	"os"

	"authzproxy/internal/auth"
	"authzproxy/internal/contextutil"
	"authzproxy/internal/observability/logging"
	"authzproxy/internal/tls"
)

// Authenticator implements mTLS authentication
type Authenticator struct {
	logger  *logging.Logger
	enabled bool
	authCAs *x509.CertPool
	tlsConf *tls.Config
}

// Config holds mTLS authenticator configuration
type Config struct {
	// Enabled indicates whether mTLS authentication is enabled
	Enabled bool

	// CAPaths is a list of paths to CA certificates for client verification
	CAPaths []string

	// TLSConfig is the TLS configuration to use (ensures same CA pool is used)
	TLSConfig *tls.Config
}

// New creates a new mTLS authenticator
func New(config Config, logger *logging.Logger) (*Authenticator, error) {
	logger = logger.WithModule("auth.mtls")

	if !config.Enabled {
		return &Authenticator{
			logger:  logger,
			enabled: false,
		}, nil
	}

	// If TLS config is provided, use its auth CAs
	if config.TLSConfig != nil && config.TLSConfig.AuthCAs != nil {
		return &Authenticator{
			logger:  logger,
			enabled: true,
			authCAs: config.TLSConfig.AuthCAs,
			tlsConf: config.TLSConfig,
		}, nil
	}

	// Otherwise, load CAs directly
	if len(config.CAPaths) == 0 {
		return nil, fmt.Errorf("mTLS authentication enabled but no CA paths provided")
	}

	// Create a new certificate pool
	authCAs := x509.NewCertPool()

	// Load CA certificates
	for _, caPath := range config.CAPaths {
		logger.Debug("Loading CA certificate", "path", caPath)

		caCert, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read mTLS CA certificate %s: %w", caPath, err)
		}

		if !authCAs.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse mTLS CA certificate %s", caPath)
		}
	}

	return &Authenticator{
		logger:  logger,
		enabled: true,
		authCAs: authCAs,
	}, nil
}

// Name returns the name of this authenticator
func (a *Authenticator) Name() string {
	return "mtls"
}

// GetMiddleware returns an http.Handler middleware that performs mTLS authentication
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

		// Skip if TLS is not enabled or no client certificates are presented
		if r.TLS == nil {
			logger.Debug("No TLS connection")
			next.ServeHTTP(w, r)
			return
		}

		// If client presented certificates, we must validate them
		// If validation fails, do not fall back to other methods
		if len(r.TLS.PeerCertificates) > 0 {
			logger.Debug("Checking peer certificates")

			// First, validate each certificate in the chain
			for _, cert := range r.TLS.PeerCertificates {
				if err := tls.VerifyCertificate(cert, a.authCAs, logger); err != nil {
					logger.Error("Client certificate verification failed", logging.Err(err))
					http.Error(w, "Client certificate verification failed", http.StatusUnauthorized)
					return // Do not fall back if validation fails
				}
			}

			logger.Debug("Starting mTLS client authentication")

			// Now check if the certificate is in the verified chains (which means it was successfully validated)
			if len(r.TLS.VerifiedChains) > 0 && len(r.TLS.VerifiedChains[0]) > 0 {
				// Get the common name from the certificate
				commonName := r.TLS.VerifiedChains[0][0].Subject.CommonName

				// Use DNS names only in development mode and if CN is empty
				if commonName == "" {
					if os.Getenv("ENVIRONMENT") == "development" && len(r.TLS.VerifiedChains[0][0].DNSNames) > 0 {
						commonName = r.TLS.VerifiedChains[0][0].DNSNames[0]
						logger.Debug("Using DNS name as subject", "dnsName", commonName)
					}

					// Reject if still empty
					if commonName == "" {
						err := fmt.Errorf("certificate Common Name is nil")
						logger.Error("mTLS Client certificate verification failed", logging.Err(err))
						http.Error(w, "Client certificate verification failed, commonName is nil", http.StatusUnauthorized)
						return
					}
				}

				logger.Debug("Client certificate verified successfully", "commonName", commonName)

				// Create identity
				identity := &auth.Identity{
					Subject:  commonName,
					Provider: a.Name(),
					Attributes: map[string]interface{}{
						"certificate": r.TLS.VerifiedChains[0][0],
					},
				}

				// Add identity and auth type to request context
				ctx = contextutil.WithIdentity(ctx, identity)
				ctx = contextutil.WithAuthType(ctx, auth.AuthTypeMTLS)

				logger.Debug("mTLS authentication successful", "subject", commonName)
			} else {
				logger.Warn("No verified client certificate chains")
				// We had certificates but they weren't properly verified
				http.Error(w, "Invalid client certificate", http.StatusUnauthorized)
				return
			}
		} else {
			logger.Debug("No client certificates presented")
		}

		// Continue with the next handler
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
