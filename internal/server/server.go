// internal/server/server.go
package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"authzproxy/internal/observability/logging"
)

// Server represents an HTTP server
type Server struct {
	httpServer      *http.Server
	metricsServer   *http.Server
	logger          *logging.Logger
	shutdownTimeout time.Duration
}

// Config holds server configuration
type Config struct {
	// Address is the address to listen on
	Address string

	// MetricsAddress is the address to listen on for metrics
	MetricsAddress string

	// TLS configuration
	TLS struct {
		// Enabled indicates whether TLS is enabled
		Enabled bool

		// Config is the TLS configuration
		Config interface{}

		// CertPath is the path to the TLS certificate
		CertPath string

		// KeyPath is the path to the TLS key
		KeyPath string
	}

	// ShutdownTimeout is the maximum time to wait for a graceful shutdown
	ShutdownTimeout time.Duration
}

// New creates a new server
func New(config Config, handler http.Handler, metricsHandler http.Handler, logger *logging.Logger) *Server {
	// Create main HTTP server
	httpServer := &http.Server{
		Addr:              config.Address,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         nil, // Will set based on config
	}

	// Set TLS config if provided
	if config.TLS.Enabled && config.TLS.Config != nil {
		if tlsConfig, ok := config.TLS.Config.(*tls.Config); ok {
			httpServer.TLSConfig = tlsConfig
		}
	}

	// Create metrics server
	metricsServer := &http.Server{
		Addr:              config.MetricsAddress,
		Handler:           metricsHandler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	return &Server{
		httpServer:      httpServer,
		metricsServer:   metricsServer,
		logger:          logger.WithModule("server"),
		shutdownTimeout: config.ShutdownTimeout,
	}
}

// Start starts the server
func (s *Server) Start() error {
	// Start metrics server
	go func() {
		s.logger.Info("Starting metrics server", "address", s.metricsServer.Addr)
		if err := s.metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Error("Metrics server failed", logging.Err(err))
		}
	}()

	// Start main server
	if s.httpServer.TLSConfig != nil {
		s.logger.Info("Starting HTTPS server", "address", s.httpServer.Addr)
		if err := s.httpServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("HTTPS server failed: %w", err)
		}
	} else {
		s.logger.Info("Starting HTTP server", "address", s.httpServer.Addr)
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("HTTP server failed: %w", err)
		}
	}

	return nil
}

// Stop stops the server gracefully
func (s *Server) Stop(ctx context.Context) error {
	s.logger.Info("Stopping servers", "timeout", s.shutdownTimeout)

	// Create a context with timeout for shutdown
	shutdownCtx, cancel := context.WithTimeout(ctx, s.shutdownTimeout)
	defer cancel()

	// Shutdown metrics server
	if err := s.metricsServer.Shutdown(shutdownCtx); err != nil {
		s.logger.Error("Failed to shut down metrics server", logging.Err(err))
	} else {
		s.logger.Info("Metrics server stopped")
	}

	// Shutdown main server
	if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
		s.logger.Error("Failed to shut down HTTP server", logging.Err(err))
		return err
	}

	s.logger.Info("HTTP server stopped")
	return nil
}
