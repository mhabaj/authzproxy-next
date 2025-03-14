// internal/tls/utils.go
package tls

import (
	"crypto/x509"
	"fmt"
	"time"

	"authzproxy/internal/observability/logging"
)

// VerifyCertificate verifies a client certificate against a CA pool
func VerifyCertificate(cert *x509.Certificate, caPool *x509.CertPool, logger *logging.Logger) error {
	opts := x509.VerifyOptions{
		Roots:         caPool,
		CurrentTime:   time.Now(),
		Intermediates: x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	_, err := cert.Verify(opts)
	if err != nil {
		if logger != nil {
			logger.Error("Client certificate verification failed", logging.Err(err))
		}
		return fmt.Errorf("client certificate verification failed: %w", err)
	}

	return nil
}

// ExtractSubject extracts the subject from a certificate
// Returns the Common Name, or the first DNS name in development mode if CN is empty
func ExtractSubject(cert *x509.Certificate, developmentMode bool) (string, error) {
	commonName := cert.Subject.CommonName

	// If commonName is empty, try to use a DNS name in development mode
	if commonName == "" && developmentMode && len(cert.DNSNames) > 0 {
		return cert.DNSNames[0], nil
	}

	if commonName == "" {
		return "", fmt.Errorf("certificate has no Common Name or valid DNS names")
	}

	return commonName, nil
}

// ValidateClientCertificates validates a slice of client certificates
func ValidateClientCertificates(certs []*x509.Certificate, caPool *x509.CertPool, logger *logging.Logger) error {
	if len(certs) == 0 {
		return fmt.Errorf("no certificates provided")
	}

	for i, cert := range certs {
		if err := VerifyCertificate(cert, caPool, logger); err != nil {
			return fmt.Errorf("certificate at position %d is invalid: %w", i, err)
		}
	}

	return nil
}
