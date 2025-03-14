// internal/server/factory.go
package server

import (
	"crypto/tls"
	"fmt"

	"authzproxy/internal/auth/manager"
	"authzproxy/internal/authz/spicedb"
	"authzproxy/internal/config"
	"authzproxy/internal/observability"
	"authzproxy/internal/observability/logging"
	"authzproxy/internal/proxy/router"
	tlsconfig "authzproxy/internal/tls"

	"github.com/authzed/authzed-go/v1"
	"github.com/authzed/grpcutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// NewFromConfig creates a new server from configuration
func NewFromConfig(cfg *config.Config) (*Server, error) {
	// Initialize observability
	obs, err := observability.NewProvider(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize observability: %w", err)
	}
	logger := obs.Logger

	// Initialize TLS configuration
	var tlsSetup *tlsconfig.Config
	var tlsCfg *tls.Config // Use standard crypto/tls.Config for the result
	if cfg.TLS.Enabled {
		tlsSetup = &tlsconfig.Config{
			Logger:      logger,
			RootCAPath:  cfg.TLS.CAPath,
			AuthCAFiles: cfg.Auth.MTLS.CAPaths,
			CertPath:    cfg.TLS.CertPath,
			KeyPath:     cfg.TLS.KeyPath,
		}

		// Create the actual TLS configuration
		var err error
		tlsCfg, err = tlsSetup.GetTLSConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS configuration: %w", err)
		}
	}

	// Initialize authentication manager
	authManager, err := manager.NewManagerFromConfig(cfg, tlsSetup, logger, obs.Metrics)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize authentication manager: %w", err)
	}

	// Initialize SpiceDB client
	spicedbClient, err := createSpiceDBClient(cfg, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create SpiceDB client: %w", err)
	}

	// Initialize authorizer
	authorizer := spicedb.New(spicedb.Config{
		ResourceType: cfg.Authz.SpiceDB.ResourceType,
		ResourceID:   cfg.Authz.SpiceDB.ResourceID,
		SubjectType:  cfg.Authz.SpiceDB.SubjectType,
	}, spicedbClient, logger)

	// Convert config.Rule to router.Rule
	routerRules := convertRules(cfg.Rules)

	// Initialize router
	routerConfig := router.Config{
		UpstreamURL:     cfg.Upstream.URL,
		UpstreamTimeout: cfg.Upstream.Timeout,
		Rules:           routerRules,
	}
	proxyRouter := router.New(routerConfig, authorizer, logger, obs.Metrics)

	// Create server configuration
	serverConfig := Config{
		Address:        cfg.Server.Address,
		MetricsAddress: cfg.Metrics.Address,
		TLS: struct {
			Enabled  bool
			Config   interface{}
			CertPath string
			KeyPath  string
		}{
			Enabled:  cfg.TLS.Enabled,
			Config:   tlsCfg, // Use the standard TLS config we generated
			CertPath: cfg.TLS.CertPath,
			KeyPath:  cfg.TLS.KeyPath,
		},
		ShutdownTimeout: cfg.Server.ShutdownTimeout,
	}

	// Create complete middleware chain: observability -> auth -> router
	handler := obs.Middleware(authManager.Middleware(proxyRouter))

	// Create and return the server
	srv := New(serverConfig, handler, obs.MetricsHandler(), logger)
	return srv, nil
}

// convertRules converts config.Rule to router.Rule
func convertRules(configRules []config.Rule) []router.Rule {
	routerRules := make([]router.Rule, len(configRules))
	for i, rule := range configRules {
		routerRules[i] = router.Rule{
			Name:        rule.Name,
			Action:      rule.Action,
			Paths:       rule.Paths,
			MatchPrefix: rule.MatchPrefix,
			Methods:     rule.Methods,
			Permission:  rule.Permission,
			Resource:    rule.Resource,
		}
	}
	return routerRules
}

// createSpiceDBClient creates a SpiceDB client
func createSpiceDBClient(cfg *config.Config, logger *logging.Logger) (*authzed.Client, error) {
	endpoint := cfg.Authz.SpiceDB.Endpoint
	token := cfg.Authz.SpiceDB.Token
	insecureConn := cfg.Authz.SpiceDB.Insecure // Renamed variable to avoid conflict

	var opts []grpc.DialOption

	if insecureConn {
		logger.Warn("Connecting to SpiceDB without TLS")
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
		opts = append(opts, grpcutil.WithInsecureBearerToken(token))
	} else {
		opts = append(opts, grpcutil.WithBearerToken(token))

		// Use system certificates by default
		logger.Debug("Using system certificates for SpiceDB")
		systemCertsOpt, err := grpcutil.WithSystemCerts(grpcutil.VerifyCA)
		if err != nil {
			logger.Error("Failed to load system certificates", logging.Err(err))
			return nil, fmt.Errorf("failed to load system certificates: %w", err)
		}
		opts = append(opts, systemCertsOpt)
	}

	logger.Info("Creating SpiceDB client", "endpoint", endpoint)
	client, err := authzed.NewClient(endpoint, opts...)
	if err != nil {
		logger.Error("Failed to create SpiceDB client", logging.Err(err))
		return nil, fmt.Errorf("failed to create SpiceDB client: %w", err)
	}

	logger.Debug("SpiceDB client created successfully")
	return client, nil
}
