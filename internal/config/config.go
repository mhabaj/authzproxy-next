// internal/config/config.go
package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Load loads the configuration from all sources and returns the merged result
func Load(configPath string) (*Config, error) {
	v := viper.New()

	// Set default values
	Settings.PopulateViperDefaults(v)

	// Set up environment variable handling
	v.SetEnvPrefix("AUTHZ")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))

	// Load from config file if specified
	if configPath != "" {
		v.SetConfigFile(configPath)
		if err := v.ReadInConfig(); err != nil {
			// It's okay if the config file doesn't exist, but other errors should be reported
			if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
				return nil, fmt.Errorf("failed to read config file: %w", err)
			}
		}
	}

	// Create the config object
	config := &Config{}

	// Populate server configuration
	config.Server.Address = v.GetString("SERVER_ADDR")
	shutdownTimeout, err := time.ParseDuration(v.GetString("SHUTDOWN_TIMEOUT"))
	if err != nil {
		return nil, fmt.Errorf("invalid shutdown timeout: %w", err)
	}
	config.Server.ShutdownTimeout = shutdownTimeout

	// Populate metrics configuration
	config.Metrics.Address = v.GetString("METRICS_ADDR")

	// Populate TLS configuration
	config.TLS.Enabled = v.GetBool("TLS_ENABLED")
	config.TLS.CertPath = v.GetString("TLS_CERT_PATH")
	config.TLS.KeyPath = v.GetString("TLS_KEY_PATH")
	config.TLS.CAPath = v.GetString("TLS_CA_PATH")

	// Populate upstream configuration
	upstreamURL, err := url.Parse(v.GetString("UPSTREAM_URL"))
	if err != nil {
		return nil, fmt.Errorf("invalid upstream URL: %w", err)
	}
	config.Upstream.URL = upstreamURL

	upstreamTimeout, err := time.ParseDuration(v.GetString("UPSTREAM_TIMEOUT"))
	if err != nil {
		return nil, fmt.Errorf("invalid upstream timeout: %w", err)
	}
	config.Upstream.Timeout = upstreamTimeout

	// Populate authentication configuration
	// mTLS
	config.Auth.MTLS.Enabled = v.GetBool("AUTH_MTLS_ENABLED")
	config.Auth.MTLS.CAPaths = v.GetStringSlice("AUTH_MTLS_CA_PATHS")

	// OIDC
	config.Auth.OIDC.Enabled = v.GetBool("AUTH_OIDC_ENABLED")
	config.Auth.OIDC.Issuer = v.GetString("AUTH_OIDC_ISSUER")
	config.Auth.OIDC.ClientID = v.GetString("AUTH_OIDC_CLIENT_ID")
	config.Auth.OIDC.ClientSecret = v.GetString("AUTH_OIDC_CLIENT_SECRET")
	config.Auth.OIDC.RedirectURL = v.GetString("AUTH_OIDC_REDIRECT_URL")
	config.Auth.OIDC.Scopes = v.GetStringSlice("AUTH_OIDC_SCOPES")
	config.Auth.OIDC.CookieName = v.GetString("AUTH_OIDC_COOKIE_NAME")
	config.Auth.OIDC.CookieSecret = v.GetString("AUTH_OIDC_COOKIE_SECRET")

	// Bearer
	config.Auth.Bearer.Enabled = v.GetBool("AUTH_BEARER_ENABLED")
	config.Auth.Bearer.Issuer = v.GetString("AUTH_BEARER_ISSUER")
	config.Auth.Bearer.ClientID = v.GetString("AUTH_BEARER_CLIENT_ID")

	// Populate authorization configuration
	config.Authz.Type = v.GetString("AUTHZ_TYPE")
	config.Authz.SpiceDB.Endpoint = v.GetString("AUTHZ_SPICEDB_ENDPOINT")
	config.Authz.SpiceDB.Insecure = v.GetBool("AUTHZ_SPICEDB_INSECURE")
	config.Authz.SpiceDB.Token = v.GetString("AUTHZ_SPICEDB_TOKEN")
	config.Authz.SpiceDB.ResourceType = v.GetString("AUTHZ_SPICEDB_RESOURCE_TYPE")
	config.Authz.SpiceDB.ResourceID = v.GetString("AUTHZ_SPICEDB_RESOURCE_ID")
	config.Authz.SpiceDB.SubjectType = v.GetString("AUTHZ_SPICEDB_SUBJECT_TYPE")

	// Populate observability configuration
	config.Observability.LogLevel = v.GetString("LOG_LEVEL")
	config.Observability.LogFormat = v.GetString("LOG_FORMAT")

	// Rules will be loaded from a separate function
	// config.Rules = loadRules(v)

	// Validate the configuration
	if err := validateConfig(config); err != nil {
		return nil, err
	}

	return config, nil
}

// validateConfig performs validation on the loaded configuration
func validateConfig(cfg *Config) error {
	// Validate required fields
	if cfg.Upstream.URL == nil || cfg.Upstream.URL.String() == "" {
		return fmt.Errorf("upstream URL is required")
	}

	// Validate TLS configuration
	if cfg.TLS.Enabled {
		if cfg.TLS.CertPath == "" {
			return fmt.Errorf("TLS certificate path is required when TLS is enabled")
		}
		if cfg.TLS.KeyPath == "" {
			return fmt.Errorf("TLS key path is required when TLS is enabled")
		}

		// Check if certificate and key files exist
		if _, err := os.Stat(cfg.TLS.CertPath); os.IsNotExist(err) {
			return fmt.Errorf("TLS certificate file not found: %s", cfg.TLS.CertPath)
		}
		if _, err := os.Stat(cfg.TLS.KeyPath); os.IsNotExist(err) {
			return fmt.Errorf("TLS key file not found: %s", cfg.TLS.KeyPath)
		}
	}

	// Validate authentication configurations
	if err := validateAuthConfig(cfg); err != nil {
		return err
	}

	// Validate authorization configurations
	if err := validateAuthzConfig(cfg); err != nil {
		return err
	}

	return nil
}

// validateAuthConfig validates authentication configuration
func validateAuthConfig(cfg *Config) error {
	// Validate mTLS configuration
	if cfg.Auth.MTLS.Enabled {
		if len(cfg.Auth.MTLS.CAPaths) == 0 {
			return fmt.Errorf("at least one CA path is required when mTLS is enabled")
		}

		// Check if CA files exist
		for _, caPath := range cfg.Auth.MTLS.CAPaths {
			if _, err := os.Stat(caPath); os.IsNotExist(err) {
				return fmt.Errorf("mTLS CA file not found: %s", caPath)
			}
		}
	}

	// Validate OIDC configuration
	if cfg.Auth.OIDC.Enabled {
		if cfg.Auth.OIDC.Issuer == "" {
			return fmt.Errorf("OIDC issuer is required when OIDC is enabled")
		}
		if cfg.Auth.OIDC.ClientID == "" {
			return fmt.Errorf("OIDC client ID is required when OIDC is enabled")
		}
		if cfg.Auth.OIDC.ClientSecret == "" {
			return fmt.Errorf("OIDC client secret is required when OIDC is enabled")
		}
		if cfg.Auth.OIDC.RedirectURL == "" {
			return fmt.Errorf("OIDC redirect URL is required when OIDC is enabled")
		}
		if cfg.Auth.OIDC.CookieSecret == "" {
			return fmt.Errorf("OIDC cookie secret is required when OIDC is enabled")
		}
	}

	// Validate Bearer configuration
	if cfg.Auth.Bearer.Enabled {
		if cfg.Auth.Bearer.Issuer == "" {
			return fmt.Errorf("Bearer issuer is required when Bearer is enabled")
		}
		if cfg.Auth.Bearer.ClientID == "" {
			return fmt.Errorf("Bearer client ID is required when Bearer is enabled")
		}
	}

	return nil
}

// validateAuthzConfig validates authorization configuration
func validateAuthzConfig(cfg *Config) error {
	if cfg.Authz.Type == "spicedb" {
		// SpiceDB validation
		if cfg.Authz.SpiceDB.Token == "" {
			return fmt.Errorf("SpiceDB token is required when using SpiceDB authorization")
		}
		if cfg.Authz.SpiceDB.ResourceID == "" {
			return fmt.Errorf("SpiceDB resource ID is required when using SpiceDB authorization")
		}
	}

	return nil
}

// LoadRules loads routing rules from a file
func LoadRules(rulesPath string) ([]Rule, error) {
	// This will be implemented later
	return nil, nil
}
