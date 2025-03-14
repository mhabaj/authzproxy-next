// internal/contextutil/context.go
package contextutil

import (
	"context"

	"authzproxy/internal/auth"
	"authzproxy/internal/observability/logging"
)

// Key is a type-safe key for context values
type Key string

const (
	// LoggerKey is the key for the logger
	LoggerKey Key = "context:logger"

	// TraceIDKey is the key for the trace ID
	TraceIDKey Key = "context:trace_id"

	// SpanIDKey is the key for the span ID
	SpanIDKey Key = "context:span_id"

	// IdentityKey is the key for the identity
	IdentityKey Key = "context:identity"

	// AuthTypeKey is the key for the authentication type
	AuthTypeKey Key = "context:auth_type"

	// RequestIDKey is the key for the request ID
	RequestIDKey Key = "context:request_id"
)

// WithLogger adds a logger to a context
func WithLogger(ctx context.Context, logger *logging.Logger) context.Context {
	return context.WithValue(ctx, LoggerKey, logger)
}

// GetLogger retrieves a logger from a context
func GetLogger(ctx context.Context) *logging.Logger {
	if logger, ok := ctx.Value(LoggerKey).(*logging.Logger); ok {
		return logger
	}
	return nil
}

// WithTraceID adds a trace ID to a context
func WithTraceID(ctx context.Context, traceID string) context.Context {
	return context.WithValue(ctx, TraceIDKey, traceID)
}

// GetTraceID retrieves a trace ID from a context
func GetTraceID(ctx context.Context) string {
	if traceID, ok := ctx.Value(TraceIDKey).(string); ok {
		return traceID
	}
	return ""
}

// WithSpanID adds a span ID to a context
func WithSpanID(ctx context.Context, spanID string) context.Context {
	return context.WithValue(ctx, SpanIDKey, spanID)
}

// GetSpanID retrieves a span ID from a context
func GetSpanID(ctx context.Context) string {
	if spanID, ok := ctx.Value(SpanIDKey).(string); ok {
		return spanID
	}
	return ""
}

// WithIdentity adds an identity to a context
func WithIdentity(ctx context.Context, identity *auth.Identity) context.Context {
	return context.WithValue(ctx, IdentityKey, identity)
}

// GetIdentity retrieves an identity from a context
func GetIdentity(ctx context.Context) *auth.Identity {
	if identity, ok := ctx.Value(IdentityKey).(*auth.Identity); ok {
		return identity
	}
	return nil
}

// WithAuthType adds an authentication type to a context
func WithAuthType(ctx context.Context, authType auth.AuthType) context.Context {
	return context.WithValue(ctx, AuthTypeKey, authType)
}

// GetAuthType retrieves an authentication type from a context
func GetAuthType(ctx context.Context) auth.AuthType {
	if authType, ok := ctx.Value(AuthTypeKey).(auth.AuthType); ok {
		return authType
	}
	return ""
}

// WithRequestID adds a request ID to a context
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, RequestIDKey, requestID)
}

// GetRequestID retrieves a request ID from a context
func GetRequestID(ctx context.Context) string {
	if requestID, ok := ctx.Value(RequestIDKey).(string); ok {
		return requestID
	}
	return ""
}

// EnrichContext adds standard observability items to a context
func EnrichContext(ctx context.Context, logger *logging.Logger) context.Context {
	traceID := GetTraceID(ctx)
	if traceID == "" {
		traceID = logging.NewTraceID()
		ctx = WithTraceID(ctx, traceID)
	}

	spanID := logging.NewSpanID()
	ctx = WithSpanID(ctx, spanID)

	if logger != nil {
		logger = logger.With(
			logging.TraceIDKey, traceID,
			logging.SpanIDKey, spanID,
		)
		ctx = WithLogger(ctx, logger)
	}

	return ctx
}

// For backward compatibility with code using auth package directly
func IdentityFromContext(ctx context.Context) *auth.Identity {
	return GetIdentity(ctx)
}

// For backward compatibility with code using auth package directly
func ContextWithIdentity(ctx context.Context, identity *auth.Identity) context.Context {
	return WithIdentity(ctx, identity)
}

// For backward compatibility with code using auth package directly
func AuthTypeFromContext(ctx context.Context) auth.AuthType {
	return GetAuthType(ctx)
}

// For backward compatibility with code using auth package directly
func ContextWithAuthType(ctx context.Context, authType auth.AuthType) context.Context {
	return WithAuthType(ctx, authType)
}
