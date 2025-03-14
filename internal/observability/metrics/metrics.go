package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Common label names for consistent metrics
const (
	LabelRule    = "rule"
	LabelAction  = "action"
	LabelStatus  = "status"
	LabelMethod  = "method"
	LabelPath    = "path"
	LabelAuth    = "auth_type"
	LabelSuccess = "success"
)

var (
	// RequestsTotal counts all HTTP requests
	RequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "authzproxy_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{LabelMethod, LabelPath, LabelStatus},
	)

	// RequestDuration tracks the duration of HTTP requests
	RequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "authzproxy_request_duration_seconds",
			Help:    "Duration of HTTP requests in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{LabelMethod, LabelPath},
	)

	// AuthenticationTotal counts authentication attempts by type and outcome
	AuthenticationTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "authzproxy_authentication_total",
			Help: "Total number of authentication attempts",
		},
		[]string{LabelAuth, LabelSuccess},
	)

	// AuthorizationTotal counts authorization checks by permission and outcome
	AuthorizationTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "authzproxy_authorization_total",
			Help: "Total number of authorization checks",
		},
		[]string{"permission", LabelSuccess},
	)

	// RuleMatchTotal counts rule matches by rule name and action
	RuleMatchTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "authzproxy_rule_match_total",
			Help: "Total number of rule matches",
		},
		[]string{LabelRule, LabelAction},
	)

	// UpstreamRequestTotal counts requests to upstream services
	UpstreamRequestTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "authzproxy_upstream_requests_total",
			Help: "Total number of requests to upstream services",
		},
		[]string{LabelMethod, "upstream", LabelStatus},
	)

	// UpstreamRequestDuration tracks the duration of upstream requests
	UpstreamRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "authzproxy_upstream_request_duration_seconds",
			Help:    "Duration of requests to upstream services in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{LabelMethod, "upstream"},
	)
)

// Collector provides methods for recording metrics
type Collector struct{}

// NewCollector creates a new metrics collector
func NewCollector() *Collector {
	return &Collector{}
}

// RecordRequest records metrics for an HTTP request
func (c *Collector) RecordRequest(method, path string, status int, duration time.Duration) {
	RequestsTotal.WithLabelValues(method, path, http.StatusText(status)).Inc()
	RequestDuration.WithLabelValues(method, path).Observe(duration.Seconds())
}

// RecordAuthentication records an authentication attempt
func (c *Collector) RecordAuthentication(authType string, success bool) {
	AuthenticationTotal.WithLabelValues(authType, boolToString(success)).Inc()
}

// RecordAuthorization records an authorization check
func (c *Collector) RecordAuthorization(permission string, success bool) {
	AuthorizationTotal.WithLabelValues(permission, boolToString(success)).Inc()
}

// RecordRuleMatch records a rule match
func (c *Collector) RecordRuleMatch(ruleName, action string) {
	RuleMatchTotal.WithLabelValues(ruleName, action).Inc()
}

// RecordUpstreamRequest records a request to an upstream service
func (c *Collector) RecordUpstreamRequest(method, upstream string, status int, duration time.Duration) {
	UpstreamRequestTotal.WithLabelValues(method, upstream, http.StatusText(status)).Inc()
	UpstreamRequestDuration.WithLabelValues(method, upstream).Observe(duration.Seconds())
}

// Handler returns an HTTP handler for exposing metrics
func Handler() http.Handler {
	return promhttp.Handler()
}

// boolToString converts a boolean to a string representation
func boolToString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
