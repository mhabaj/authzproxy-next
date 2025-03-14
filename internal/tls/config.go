// internal/tls/config.go
package tls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"authzproxy/internal/observability/logging"
)

// Config holds the TLS configuration
type Config struct {
	// Logger is the logger to use
	Logger *logging.Logger

	// RootCAPath is the path to the root CA certificate
	RootCAPath string

	// AuthCAFiles is a list of paths to CA certificates for client verification
	AuthCAFiles []string

	// CertPath is the path to the server certificate
	CertPath string

	// KeyPath is the path to the server key
	KeyPath string

	// AuthCAs is the certificate pool for client verification
	AuthCAs *x509.CertPool
}

// GetTLSConfig creates a TLS configuration for the server
func (c *Config) GetTLSConfig() (*tls.Config, error) {
	c.Logger.Debug("Initializing TLS configuration")

	// Create certificate pools
	rootCAPool := x509.NewCertPool()

	// Load root CA if provided
	if c.RootCAPath != "" {
		rootCA, err := os.ReadFile(c.RootCAPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read root CA file: %w", err)
		}
		if !rootCAPool.AppendCertsFromPEM(rootCA) {
			return nil, fmt.Errorf("failed to parse root CA file: %s", c.RootCAPath)
		}
		c.Logger.Debug("Root CA loaded for TLS", "RootCAFile", c.RootCAPath)
	}

	// Initialize TLS config with the root CA pool
	tlsConfig := &tls.Config{
		ClientCAs:  rootCAPool,
		ClientAuth: tls.VerifyClientCertIfGiven, // Allow but don't require client certs
		MinVersion: tls.VersionTLS12,            // Enforce minimum TLS version
	}

	// Load auth CA files if provided
	if len(c.AuthCAFiles) > 0 {
		authCAPool := x509.NewCertPool()
		for _, authCAFile := range c.AuthCAFiles {
			authCA, err := os.ReadFile(authCAFile)
			if err != nil {
				return nil, fmt.Errorf("failed to read auth CA file: %w", err)
			}
			if !authCAPool.AppendCertsFromPEM(authCA) {
				return nil, fmt.Errorf("failed to parse auth CA file: %s", authCAFile)
			}
			c.Logger.Debug("Auth CA file loaded for mTLS", "AuthCAFile", authCAFile)
		}
		c.AuthCAs = authCAPool
		tlsConfig.ClientCAs = authCAPool
		tlsConfig.VerifyPeerCertificate = c.getClientValidator()
		c.Logger.Debug("mTLS configured with client certificate validation")
	} else if len(c.AuthCAFiles) == 0 && c.RootCAPath != "" {
		c.Logger.Warn("mTLS is enabled but no AuthCAFiles were provided, using RootCA")
		c.AuthCAs = rootCAPool
	}

	c.Logger.Info("TLS configuration successful")
	return tlsConfig, nil
}

// getClientValidator returns a function to validate client certificates
func (c *Config) getClientValidator() func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(verifiedChains) == 0 {
			c.Logger.Debug("No client certificate provided, continuing without mTLS identity")
			return nil
		}

		// If a cert chain is present but empty, it's invalid
		if len(verifiedChains[0]) == 0 {
			return fmt.Errorf("client certificate is invalid (empty chain)")
		}

		opts := x509.VerifyOptions{
			Roots:         c.AuthCAs,
			CurrentTime:   time.Now(),
			Intermediates: x509.NewCertPool(),
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}

		_, err := verifiedChains[0][0].Verify(opts)
		if err != nil {
			c.Logger.Error("Client certificate verification failed", logging.Err(err))
			return fmt.Errorf("client certificate verification failed: %w", err)
		}

		c.Logger.Debug("Client certificate verified successfully", "subject", verifiedChains[0][0].Subject.CommonName)
		return nil
	}
}
