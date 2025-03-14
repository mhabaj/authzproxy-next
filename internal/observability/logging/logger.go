package logging

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lmittmann/tint"
)

// Constants for context and attribute keys
const (
	TraceIDKey = "trace_id"
	SpanIDKey  = "span_id"
	ModuleKey  = "module"
)

// programLevel allows dynamic adjustment of logging level
var programLevel = new(slog.LevelVar)

// Logger wraps slog.Logger with additional functionality
type Logger struct {
	*slog.Logger
}

// filterAttr filters out specific attributes to reduce log verbosity
func filterAttr(groups []string, a slog.Attr) slog.Attr {
	// Filter out sensitive data
	if a.Key == "password" || a.Key == "secret" || a.Key == "token" ||
		a.Key == "apiKey" || a.Key == "sensitive_data" {
		return slog.Attr{}
	}
	return a
}

// NewLogger creates a new logger with the specified level
func NewLogger(level string) (*Logger, error) {
	// Create a handler with tint for better readability
	handler := tint.NewHandler(os.Stdout, &tint.Options{
		Level:       programLevel,
		TimeFormat:  time.RFC3339,
		ReplaceAttr: filterAttr,
	})

	// Set the log level
	if err := SetLogLevel(level); err != nil {
		return nil, err
	}

	logger := &Logger{
		Logger: slog.New(handler),
	}

	// Set as default logger
	slog.SetDefault(logger.Logger)

	return logger, nil
}

// SetLogLevel sets the logging level
func SetLogLevel(level string) error {
	switch strings.ToLower(level) {
	case "debug":
		programLevel.Set(slog.LevelDebug)
	case "info":
		programLevel.Set(slog.LevelInfo)
	case "warn":
		programLevel.Set(slog.LevelWarn)
	case "error":
		programLevel.Set(slog.LevelError)
	default:
		return fmt.Errorf("invalid log level: '%s'", level)
	}
	return nil
}

// GetLogLevel returns the current logging level
func GetLogLevel() slog.Level {
	return programLevel.Level()
}

// IsDebugEnabled returns true if debug logging is enabled
func IsDebugEnabled() bool {
	return programLevel.Level() <= slog.LevelDebug
}

// With creates a new logger with the provided attributes
func (l *Logger) With(args ...any) *Logger {
	return &Logger{
		Logger: l.Logger.With(args...),
	}
}

// WithModule creates a new logger with the module attribute
func (l *Logger) WithModule(module string) *Logger {
	return l.With(ModuleKey, module)
}

// WithTracing adds trace and span IDs to the logger
func (l *Logger) WithTracing(traceID string) *Logger {
	logger, _, _ := l.WithTracingAndIDs(traceID)
	return logger
}

// WithTracingAndIDs adds trace and span IDs to the logger and returns them
func (l *Logger) WithTracingAndIDs(traceID string) (*Logger, string, string) {
	if strings.TrimSpace(traceID) == "" {
		traceID = NewTraceID()
	}

	spanID := NewSpanID()

	return l.With(TraceIDKey, traceID, SpanIDKey, spanID), traceID, spanID
}

// WithContext creates a logger with context values (particularly trace information)
func (l *Logger) WithContext(ctx context.Context) *Logger {
	// Extract trace ID from context if available
	traceID := GetTraceIDFromContext(ctx)
	if traceID == "" {
		traceID = NewTraceID()
		ctx = context.WithValue(ctx, ctxTraceIDKey, traceID)
	}

	// Extract or generate span ID
	spanID := GetSpanIDFromContext(ctx)
	if spanID == "" {
		spanID = NewSpanID()
		ctx = context.WithValue(ctx, ctxSpanIDKey, spanID)
	}

	return l.With(TraceIDKey, traceID, SpanIDKey, spanID)
}

// NewTraceID generates a new trace ID
func NewTraceID() string {
	return uuid.NewString()
}

// NewSpanID generates a new span ID
func NewSpanID() string {
	return uuid.NewString()
}

// Context key type for logging context
type contextKey string

// Context keys
const (
	ctxLoggerKey  contextKey = "logger"
	ctxTraceIDKey contextKey = "traceID"
	ctxSpanIDKey  contextKey = "spanID"
)

// ContextWithLogger adds a logger to a context
func ContextWithLogger(ctx context.Context, logger *Logger) context.Context {
	return context.WithValue(ctx, ctxLoggerKey, logger)
}

// LoggerFromContext extracts a logger from a context
func LoggerFromContext(ctx context.Context) *Logger {
	if logger, ok := ctx.Value(ctxLoggerKey).(*Logger); ok {
		return logger
	}
	return nil
}

// GetTraceIDFromContext retrieves the trace ID from context
func GetTraceIDFromContext(ctx context.Context) string {
	if traceID, ok := ctx.Value(ctxTraceIDKey).(string); ok {
		return traceID
	}
	return ""
}

// GetSpanIDFromContext retrieves the span ID from context
func GetSpanIDFromContext(ctx context.Context) string {
	if spanID, ok := ctx.Value(ctxSpanIDKey).(string); ok {
		return spanID
	}
	return ""
}

// ContextWithTraceID adds a trace ID to context
func ContextWithTraceID(ctx context.Context, traceID string) context.Context {
	return context.WithValue(ctx, ctxTraceIDKey, traceID)
}

// ContextWithSpanID adds a span ID to context
func ContextWithSpanID(ctx context.Context, spanID string) context.Context {
	return context.WithValue(ctx, ctxSpanIDKey, spanID)
}

// Err returns a formatted error attribute for logging
func Err(err error) slog.Attr {
	return tint.Err(err)
}
