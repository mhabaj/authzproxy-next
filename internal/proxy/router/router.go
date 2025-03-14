// internal/proxy/router/router.go
package router

import (
	"net/http"
	"net/http/httputil"
	"net/url"

	"authzproxy/internal/auth"
	"authzproxy/internal/authz"
	"authzproxy/internal/observability/logging"
	"authzproxy/internal/observability/metrics"

	"github.com/gorilla/mux"
)

// Rule defines a routing rule
type Rule struct {
	// Name is a unique identifier for the rule
	Name string

	// Action determines what action to take for matched requests
	// Can be "allow", "deny", or "auth"
	Action string

	// Paths is a list of URL paths this rule applies to
	Paths []string

	// MatchPrefix indicates whether to match the path prefix instead of exact match
	MatchPrefix bool

	// Methods is a list of HTTP methods this rule applies to (empty = all methods)
	Methods []string

	// Permission is the permission required for "auth" action
	// Ignored for other actions
	Permission string

	// Resource is the resource identifier for authorization checks
	// If empty, the default resource from configuration is used
	Resource string
}

// Router is a proxy router that implements routing rules and authentication/authorization
type Router struct {
	*mux.Router
	target      *httputil.ReverseProxy
	authorizer  authz.Authorizer
	rules       []Rule
	logger      *logging.Logger
	metrics     *metrics.Collector
	upstreamURL *url.URL
}

// Config holds router configuration
type Config struct {
	// UpstreamURL is the URL of the upstream service
	UpstreamURL *url.URL

	// Rules is the list of routing rules
	Rules []Rule
}

// New creates a new router
func New(config Config, authorizer authz.Authorizer, logger *logging.Logger, metricsCollector *metrics.Collector) *Router {
	r := &Router{
		Router:      mux.NewRouter(),
		target:      httputil.NewSingleHostReverseProxy(config.UpstreamURL),
		authorizer:  authorizer,
		rules:       config.Rules,
		logger:      logger.WithModule("proxy.router"),
		metrics:     metricsCollector,
		upstreamURL: config.UpstreamURL,
	}

	// Set up the routes
	r.setupRoutes()

	return r
}

// setupRoutes configures routes based on rules
func (r *Router) setupRoutes() {
	for _, rule := range r.rules {
		r.logger.Debug("Setting up route",
			"name", rule.Name,
			"action", rule.Action,
			"paths", rule.Paths,
			"methods", rule.Methods,
		)

		for _, path := range rule.Paths {
			var route *mux.Route
			if rule.MatchPrefix {
				route = r.PathPrefix(path)
			} else {
				route = r.Path(path)
			}

			if len(rule.Methods) > 0 {
				route = route.Methods(rule.Methods...)
			}

			switch rule.Action {
			case "allow":
				route.HandlerFunc(r.AllowHandler(rule))
			case "deny":
				route.HandlerFunc(r.DenyHandler(rule))
			case "auth":
				route.HandlerFunc(r.AuthHandler(rule))
			default:
				r.logger.Warn("Unknown action in rule, defaulting to deny",
					"rule", rule.Name,
					"action", rule.Action,
				)
				route.HandlerFunc(r.DenyHandler(rule))
			}
		}
	}

	// Add root handler for diagnostic purposes
	r.Path("/").Methods("GET").HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.logger.Info("Root path accessed")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("AuthZ Proxy - Root path reached"))
	})

	// Add default 404 handler for any unmatched routes
	r.NotFoundHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.logger.Warn("Request received for undefined route", "path", req.URL.Path)
		r.metrics.RecordRequest(req.Method, req.URL.Path, http.StatusNotFound, 0)
		http.Error(w, "404 page not found", http.StatusNotFound)
	})
}

// AllowHandler creates a handler that allows all requests
func (r *Router) AllowHandler(rule Rule) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		// Get logger from context
		ctx := req.Context()
		logger := logging.LoggerFromContext(ctx)
		if logger == nil {
			logger = r.logger
		}

		logger.Debug("Allow handler called",
			"rule", rule.Name,
			"path", req.URL.Path,
			"method", req.Method,
		)

		// Record metrics
		r.metrics.RecordRuleMatch(rule.Name, "allow")

		// Proxy the request to the upstream service
		r.target.ServeHTTP(w, req)
	}
}

// DenyHandler creates a handler that denies all requests
func (r *Router) DenyHandler(rule Rule) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		// Get logger from context
		ctx := req.Context()
		logger := logging.LoggerFromContext(ctx)
		if logger == nil {
			logger = r.logger
		}

		logger.Debug("Deny handler called",
			"rule", rule.Name,
			"path", req.URL.Path,
			"method", req.Method,
		)

		// Record metrics
		r.metrics.RecordRuleMatch(rule.Name, "deny")

		http.Error(w, "Forbidden", http.StatusForbidden)
	}
}

// AuthHandler creates a handler that authorizes requests
func (r *Router) AuthHandler(rule Rule) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		// Get logger from context
		ctx := req.Context()
		logger := logging.LoggerFromContext(ctx)
		if logger == nil {
			logger = r.logger
		}

		logger.Debug("Auth handler called",
			"rule", rule.Name,
			"path", req.URL.Path,
			"method", req.Method,
			"permission", rule.Permission,
		)

		// Get the identity from the context
		identity := auth.IdentityFromContext(ctx)
		if identity == nil {
			logger.Info("Auth failed: no identity in context", "rule", rule.Name)
			r.metrics.RecordAuthorization(rule.Permission, false)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Create authorization request
		authReq := &authz.Request{
			Identity:   identity,
			Permission: rule.Permission,
			Resource:   rule.Resource,
			Context:    ctx, // Important: include req context for cancellation
		}

		// Check authorization
		resp := r.authorizer.Authorize(authReq)

		// Record metrics
		r.metrics.RecordRuleMatch(rule.Name, "auth")

		// Handle the response
		switch resp.Decision {
		case authz.Allow:
			logger.Debug("Authorization successful",
				"subject", identity.Subject,
				"permission", rule.Permission,
				"rule", rule.Name,
			)
			r.metrics.RecordAuthorization(rule.Permission, true)
			r.target.ServeHTTP(w, req)
		case authz.Deny:
			logger.Info("Authorization failed: permission denied",
				"subject", identity.Subject,
				"permission", rule.Permission,
				"rule", rule.Name,
			)
			r.metrics.RecordAuthorization(rule.Permission, false)
			http.Error(w, "Forbidden", http.StatusForbidden)
		case authz.Unauthorized:
			logger.Info("Authorization failed: unauthorized", "rule", rule.Name)
			r.metrics.RecordAuthorization(rule.Permission, false)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		case authz.Error:
			logger.Error("Authorization failed: error",
				logging.Err(resp.Error),
				"rule", rule.Name,
			)
			r.metrics.RecordAuthorization(rule.Permission, false)
			// IMPORTANT: Use StatusServiceUnavailable (503) not StatusInternalServerError (500)
			// This matches the original SpiceDB authorizer implementation
			http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		}
	}
}
