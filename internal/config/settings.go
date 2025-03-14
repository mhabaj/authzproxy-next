// internal/config/settings.go
package config

import "github.com/spf13/viper"

// SettingType represents the type of a setting
type SettingType string

const (
	// String type for string settings
	String SettingType = "string"
	// Bool type for boolean settings
	Bool SettingType = "bool"
	// Int type for integer settings
	Int SettingType = "int"
	// StringSlice type for string slice settings
	StringSlice SettingType = "stringSlice"
)

// Setting defines a configuration setting
type Setting struct {
	// Name is the name of the setting
	Name string
	// Short is a short description of the setting
	Short string
	// Type is the type of the setting
	Type SettingType
	// Default is the default value of the setting
	Default interface{}
	// Env is the environment variable name for the setting
	Env string
	// Required indicates whether the setting is required
	Required bool
}

// SettingList is a list of settings
type SettingList []Setting

// PopulateViperDefaults sets default values for all settings in Viper
func (sl SettingList) PopulateViperDefaults(v *viper.Viper) {
	for _, s := range sl {
		v.SetDefault(s.Name, s.Default)
	}
}

// Settings defines all application settings
var Settings = SettingList{
	// Server settings
	{
		Name:    "SERVER_ADDR",
		Short:   "Address on which the server listens",
		Type:    String,
		Default: ":8000",
		Env:     "SERVER_ADDR",
	},
	{
		Name:    "METRICS_ADDR",
		Short:   "Address on which the metrics server listens",
		Type:    String,
		Default: ":9090",
		Env:     "METRICS_ADDR",
	},
	{
		Name:    "SHUTDOWN_TIMEOUT",
		Short:   "Maximum time to wait for graceful shutdown",
		Type:    String,
		Default: "30s",
		Env:     "SHUTDOWN_TIMEOUT",
	},

	// TLS settings
	{
		Name:    "TLS_ENABLED",
		Short:   "Enable TLS for the server",
		Type:    Bool,
		Default: false,
		Env:     "TLS_ENABLED",
	},
	{
		Name:    "TLS_CERT_PATH",
		Short:   "Path to TLS certificate file",
		Type:    String,
		Default: "",
		Env:     "TLS_CERT_PATH",
	},
	{
		Name:    "TLS_KEY_PATH",
		Short:   "Path to TLS key file",
		Type:    String,
		Default: "",
		Env:     "TLS_KEY_PATH",
	},
	{
		Name:    "TLS_CA_PATH",
		Short:   "Path to TLS CA certificate file",
		Type:    String,
		Default: "",
		Env:     "TLS_CA_PATH",
	},

	// Upstream settings
	{
		Name:    "UPSTREAM_URL",
		Short:   "URL of the upstream service",
		Type:    String,
		Default: "",
		Env:     "UPSTREAM_URL",
		Required: true,
	},
	{
		Name:    "UPSTREAM_TIMEOUT",
		Short:   "Timeout for upstream requests",
		Type:    String,
		Default: "30s",
		Env:     "UPSTREAM_TIMEOUT",
	},

	// Authentication: mTLS
	{
		Name:    "AUTH_MTLS_ENABLED",
		Short:   "Enable mTLS authentication",
		Type:    Bool,
		Default: false,
		Env:     "AUTH_MTLS_ENABLED",
	},
	{
		Name:    "AUTH_MTLS_CA_PATHS",
		Short:   "Paths to CA certificates for client verification",
		Type:    StringSlice,
		Default: []string{},
		Env:     "AUTH_MTLS_CA_PATHS",
	},

	// Authentication: OIDC
	{
		Name:    "AUTH_OIDC_ENABLED",
		Short:   "Enable OIDC authentication",
		Type:    Bool,
		Default: false,
		Env:     "AUTH_OIDC_ENABLED",
	},
	{
		Name:    "AUTH_OIDC_ISSUER",
		Short:   "OIDC issuer URL",
		Type:    String,
		Default: "",
		Env:     "AUTH_OIDC_ISSUER",
	},
	{
		Name:    "AUTH_OIDC_CLIENT_ID",
		Short:   "OIDC client ID",
		Type:    String,
		Default: "",
		Env:     "AUTH_OIDC_CLIENT_ID",
	},
	{
		Name:    "AUTH_OIDC_CLIENT_SECRET",
		Short:   "OIDC client secret",
		Type:    String,
		Default: "",
		Env:     "AUTH_OIDC_CLIENT_SECRET",
	},
	{
		Name:    "AUTH_OIDC_REDIRECT_URL",
		Short:   "OIDC redirect URL",
		Type:    String,
		Default: "",
		Env:     "AUTH_OIDC_REDIRECT_URL",
	},
	{
		Name:    "AUTH_OIDC_SCOPES",
		Short:   "OIDC scopes",
		Type:    StringSlice,
		Default: []string{"openid", "email", "profile"},
		Env:     "AUTH_OIDC_SCOPES",
	},
	{
		Name:    "AUTH_OIDC_COOKIE_NAME",
		Short:   "Name of the OIDC session cookie",
		Type:    String,
		Default: "authzproxy_session",
		Env:     "AUTH_OIDC_COOKIE_NAME",
	},
	{
		Name:    "AUTH_OIDC_COOKIE_SECRET",
		Short:   "Secret key for OIDC session cookie encryption",
		Type:    String,
		Default: "",
		Env:     "AUTH_OIDC_COOKIE_SECRET",
	},

	// Authentication: Bearer
	{
		Name:    "AUTH_BEARER_ENABLED",
		Short:   "Enable Bearer token authentication",
		Type:    Bool,
		Default: false,
		Env:     "AUTH_BEARER_ENABLED",
	},
	{
		Name:    "AUTH_BEARER_ISSUER",
		Short:   "Bearer token issuer",
		Type:    String,
		Default: "",
		Env:     "AUTH_BEARER_ISSUER",
	},
	{
		Name:    "AUTH_BEARER_CLIENT_ID",
		Short:   "Bearer token client ID",
		Type:    String,
		Default: "",
		Env:     "AUTH_BEARER_CLIENT_ID",
	},

	// Authorization: SpiceDB
	{
		Name:    "AUTHZ_TYPE",
		Short:   "Type of authorizer to use (spicedb, simple)",
		Type:    String,
		Default: "spicedb",
		Env:     "AUTHZ_TYPE",
	},
	{
		Name:    "AUTHZ_SPICEDB_ENDPOINT",
		Short:   "SpiceDB endpoint",
		Type:    String,
		Default: "localhost:50051",
		Env:     "AUTHZ_SPICEDB_ENDPOINT",
	},
	{
		Name:    "AUTHZ_SPICEDB_INSECURE",
		Short:   "Use insecure connection to SpiceDB",
		Type:    Bool,
		Default: false,
		Env:     "AUTHZ_SPICEDB_INSECURE",
	},
	{
		Name:    "AUTHZ_SPICEDB_TOKEN",
		Short:   "SpiceDB authentication token",
		Type:    String,
		Default: "",
		Env:     "AUTHZ_SPICEDB_TOKEN",
	},
	{
		Name:    "AUTHZ_SPICEDB_RESOURCE_TYPE",
		Short:   "SpiceDB resource type",
		Type:    String,
		Default: "instance",
		Env:     "AUTHZ_SPICEDB_RESOURCE_TYPE",
	},
	{
		Name:    "AUTHZ_SPICEDB_RESOURCE_ID",
		Short:   "SpiceDB resource ID",
		Type:    String,
		Default: "",
		Env:     "AUTHZ_SPICEDB_RESOURCE_ID",
	},
	{
		Name:    "AUTHZ_SPICEDB_SUBJECT_TYPE",
		Short:   "SpiceDB subject type",
		Type:    String,
		Default: "user",
		Env:     "AUTHZ_SPICEDB_SUBJECT_TYPE",
	},

	// Observability
	{
		Name:    "LOG_LEVEL",
		Short:   "Logging level",
		Type:    String,
		Default: "info",
		Env:     "LOG_LEVEL",
	},
	{
		Name:    "LOG_FORMAT",
		Short:   "Logging format (json, text, console)",
		Type:    String,
		Default: "json",
		Env:     "LOG_FORMAT",
	},
}