package observability

import (
	"net/http"
	"time"

	"authzproxy/internal/config"
	"authzproxy/internal/observability/logging"
	"authzproxy/internal/observability/metrics"
)

// Provider provides observability capabilities
type Provider struct {
	Logger  *logging.Logger
	Metrics *metrics.Collector
}

// NewProvider creates a new observability provider
func NewProvider(cfg *config.Config) (*Provider, error) {
	// Create logger
	logger, err := logging.NewLogger(cfg.Observability.LogLevel)
	if err != nil {
		return nil, err
	}

	// Create metrics collector
	metricsCollector := metrics.NewCollector()

	return &Provider{
		Logger:  logger,
		Metrics: metricsCollector,
	}, nil
}

// Middleware creates an HTTP middleware for request observation
func (p *Provider) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()

		// Extract or create trace and span IDs
		ctx := r.Context()
		traceID := logging.GetTraceIDFromContext(ctx)
		if traceID == "" {
			traceID = logging.NewTraceID()
			ctx = logging.ContextWithTraceID(ctx, traceID)
		}

		spanID := logging.NewSpanID()
		ctx = logging.ContextWithSpanID(ctx, spanID)

		// Attach logger to context
		logger := p.Logger.WithTracing(traceID).With(logging.SpanIDKey, spanID)
		ctx = logging.ContextWithLogger(ctx, logger)

		// Create a response wrapper to capture the status code
		wrapper := newResponseWrapper(w)

		// Add trace information to response headers
		wrapper.Header().Set("X-Trace-ID", traceID)

		// Log the incoming request
		logger.Info("Request started",
			"method", r.Method,
			"path", r.URL.Path,
			"remote_addr", r.RemoteAddr,
			"user_agent", r.UserAgent(),
		)

		// Update request with context
		r = r.WithContext(ctx)

		// Call the next handler
		next.ServeHTTP(wrapper, r)

		// Record request duration and status
		duration := time.Since(startTime)

		// Record metrics
		p.Metrics.RecordRequest(r.Method, r.URL.Path, wrapper.statusCode, duration)

		// Log the completed request
		logger.Info("Request completed",
			"method", r.Method,
			"path", r.URL.Path,
			"status", wrapper.statusCode,
			"duration_ms", duration.Milliseconds(),
		)
	})
}

// HTTPHandler wraps a handler func with observability
func (p *Provider) HTTPHandler(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()

		// Create a new context with trace information
		ctx := r.Context()
		traceID := logging.NewTraceID()
		spanID := logging.NewSpanID()

		ctx = logging.ContextWithTraceID(ctx, traceID)
		ctx = logging.ContextWithSpanID(ctx, spanID)

		// Add logger to context
		logger := p.Logger.With(
			logging.TraceIDKey, traceID,
			logging.SpanIDKey, spanID,
		)
		ctx = logging.ContextWithLogger(ctx, logger)

		// Create response wrapper
		wrapper := newResponseWrapper(w)
		wrapper.Header().Set("X-Trace-ID", traceID)

		// Update request with new context
		r = r.WithContext(ctx)

		// Execute handler
		h(wrapper, r)

		// Record metrics
		duration := time.Since(startTime)
		p.Metrics.RecordRequest(r.Method, r.URL.Path, wrapper.statusCode, duration)
	}
}

// responseWrapper is a wrapper for http.ResponseWriter that captures the status code
type responseWrapper struct {
	http.ResponseWriter
	statusCode int
}

// newResponseWrapper creates a new response wrapper
func newResponseWrapper(w http.ResponseWriter) *responseWrapper {
	return &responseWrapper{ResponseWriter: w, statusCode: http.StatusOK}
}

// WriteHeader captures the status code and passes it to the underlying ResponseWriter
func (rw *responseWrapper) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// MetricsHandler returns an HTTP handler for exposing metrics
func (p *Provider) MetricsHandler() http.Handler {
	return metrics.Handler()
}
