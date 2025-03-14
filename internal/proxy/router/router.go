// internal/proxy/router/router.go
package router

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"authzproxy/internal/authz"
	"authzproxy/internal/contextutil"
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

	// UpstreamTimeout is the timeout for upstream service requests
	UpstreamTimeout time.Duration

	// Rules is the list of routing rules
	Rules []Rule
}

// New creates a new router
func New(config Config, authorizer authz.Authorizer, logger *logging.Logger, metricsCollector *metrics.Collector) *Router {
	// Create the reverse proxy with proper timeout configuration
	target := httputil.NewSingleHostReverseProxy(config.UpstreamURL)

	// Configure transport with timeouts
	transport := &http.Transport{
		ResponseHeaderTimeout: config.UpstreamTimeout,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	target.Transport = transport

	// Set up upstream request metrics
	target.ModifyResponse = func(resp *http.Response) error {
		req := resp.Request
		if req != nil {
			startTime := time.Now().Add(-config.UpstreamTimeout) // Approximate start time
			duration := time.Since(startTime)
			metricsCollector.RecordUpstreamRequest(
				req.Method,
				config.UpstreamURL.String(),
				resp.StatusCode,
				duration,
			)
		}
		return nil
	}

	r := &Router{
		Router:      mux.NewRouter(),
		target:      target,
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
	// Create reusable handlers
	allowHandler := r.createAllowHandler()
	denyHandler := r.createDenyHandler()

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

			// Store rule data in route variables
			route = route.Name(rule.Name)

			switch rule.Action {
			case "allow":
				route.Handler(allowHandler)
			case "deny":
				route.Handler(denyHandler)
			case "auth":
				// Auth handler needs permission, so we create a specific handler
				route.Handler(r.createAuthHandlerForRule(rule))
			default:
				r.logger.Warn("Unknown action in rule, defaulting to deny",
					"rule", rule.Name, "action", rule.Action)
				route.Handler(denyHandler)
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

// createAllowHandler creates a reusable handler for "allow" rules
func (r *Router) createAllowHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Get the rule name from the route
		route := mux.CurrentRoute(req)
		ruleName := route.GetName()

		// Get logger from context
		ctx := req.Context()
		logger := logging.LoggerFromContext(ctx)
		if logger == nil {
			logger = r.logger
		}

		logger.Debug("Allow handler called",
			"rule", ruleName,
			"path", req.URL.Path,
			"method", req.Method,
		)

		// Record metrics
		r.metrics.RecordRuleMatch(ruleName, "allow")

		// Start time for measuring upstream request duration
		startTime := time.Now()

		// Create a response writer wrapper to capture status
		wrapper := newResponseWrapper(w)

		// Proxy to upstream
		r.target.ServeHTTP(wrapper, req)

		// Record metrics
		duration := time.Since(startTime)
		r.metrics.RecordUpstreamRequest(req.Method, r.upstreamURL.String(), wrapper.statusCode, duration)
	})
}

// createDenyHandler creates a reusable handler for "deny" rules
func (r *Router) createDenyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Get the rule name from the route
		route := mux.CurrentRoute(req)
		ruleName := route.GetName()

		// Get logger from context
		ctx := req.Context()
		logger := logging.LoggerFromContext(ctx)
		if logger == nil {
			logger = r.logger
		}

		logger.Debug("Deny handler called",
			"rule", ruleName,
			"path", req.URL.Path,
			"method", req.Method,
		)

		// Record metrics
		r.metrics.RecordRuleMatch(ruleName, "deny")

		http.Error(w, "Forbidden", http.StatusForbidden)
	})
}

// createAuthHandlerForRule creates a handler for a specific "auth" rule
func (r *Router) createAuthHandlerForRule(rule Rule) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Context and logging setup
		ctx := req.Context()
		logger := logging.LoggerFromContext(ctx)
		if logger == nil {
			logger = r.logger
		}

		logger.Debug("Auth handler called",
			"rule", rule.Name,
			"permission", rule.Permission,
			"path", req.URL.Path,
			"method", req.Method,
		)

		// Get identity and authorize
		identity := contextutil.GetIdentity(ctx)
		if identity == nil {
			logger.Info("Auth failed: no identity", "rule", rule.Name)
			r.metrics.RecordAuthorization(rule.Permission, false)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Create authorization request
		authzReq := &authz.Request{
			Identity:   identity,
			Permission: rule.Permission,
			Resource:   rule.Resource,
			Context:    ctx, // Important: include req context for cancellation
		}

		// Check authorization
		resp := r.authorizer.Authorize(authzReq)

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

			// Start time for measuring upstream request duration
			startTime := time.Now()

			// Create a response writer wrapper to capture status
			wrapper := newResponseWrapper(w)

			// Proxy to upstream
			r.target.ServeHTTP(wrapper, req)

			// Record metrics
			duration := time.Since(startTime)
			r.metrics.RecordUpstreamRequest(req.Method, r.upstreamURL.String(), wrapper.statusCode, duration)

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
	})
}

// responseWrapper is a wrapper for http.ResponseWriter that captures status code
type responseWrapper struct {
	http.ResponseWriter
	statusCode int
}

// newResponseWrapper creates a new response wrapper
func newResponseWrapper(w http.ResponseWriter) *responseWrapper {
	return &responseWrapper{ResponseWriter: w, statusCode: http.StatusOK}
}

// WriteHeader captures the status code before passing to the underlying ResponseWriter
func (rw *responseWrapper) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
