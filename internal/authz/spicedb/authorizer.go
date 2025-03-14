// internal/authz/spicedb/authorizer.go
package spicedb

import (
	"net/http"

	"authzproxy/internal/auth"
	"authzproxy/internal/authz"
	"authzproxy/internal/observability/logging"

	v1pb "github.com/authzed/authzed-go/proto/authzed/api/v1"
	"github.com/authzed/authzed-go/v1"
)

// Authorizer implements authorization using SpiceDB
type Authorizer struct {
	client       *authzed.Client
	resourceType string
	resourceID   string
	subjectType  string
	logger       *logging.Logger
}

// Config holds SpiceDB authorizer configuration
type Config struct {
	// Endpoint is the SpiceDB endpoint
	Endpoint string

	// Insecure indicates whether to use an insecure connection
	Insecure bool

	// Token is the SpiceDB authentication token
	Token string

	// ResourceType is the SpiceDB resource type
	ResourceType string

	// ResourceID is the SpiceDB resource ID
	ResourceID string

	// SubjectType is the SpiceDB subject type
	SubjectType string
}

// New creates a new SpiceDB authorizer
func New(config Config, client *authzed.Client, logger *logging.Logger) *Authorizer {
	return &Authorizer{
		client:       client,
		resourceType: config.ResourceType,
		resourceID:   config.ResourceID,
		subjectType:  config.SubjectType,
		logger:       logger.WithModule("authz.spicedb"),
	}
}

// Authorize checks if the identity has the specified permission on the resource
func (a *Authorizer) Authorize(req *authz.Request) *authz.Response {
	// If no identity, return Unauthorized
	if req.Identity == nil {
		return &authz.Response{
			Decision: authz.Unauthorized,
			Reason:   "No identity provided",
		}
	}

	// Determine resource ID to use
	resourceID := req.Resource
	if resourceID == "" {
		resourceID = a.resourceID
	}

	// Create SpiceDB check request
	checkReq := &v1pb.CheckPermissionRequest{
		Resource: &v1pb.ObjectReference{
			ObjectType: a.resourceType,
			ObjectId:   resourceID,
		},
		Permission: req.Permission,
		Subject: &v1pb.SubjectReference{
			Object: &v1pb.ObjectReference{
				ObjectType: a.subjectType,
				ObjectId:   req.Identity.Subject,
			},
		},
	}

	// Send the check request - IMPORTANT: Use the request context for proper cancellation
	resp, err := a.client.CheckPermission(req.Context, checkReq)
	if err != nil {
		a.logger.Error("Error checking permission with SpiceDB",
			logging.Err(err),
			"subject", req.Identity.Subject,
			"resource", resourceID,
			"permission", req.Permission,
		)
		return &authz.Response{
			Decision: authz.Error,
			Reason:   "Error checking permission",
			Error:    err,
		}
	}

	// Determine the decision based on the response
	if resp.GetPermissionship() == v1pb.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION {
		return &authz.Response{
			Decision: authz.Allow,
			Reason:   "Permission granted",
		}
	}

	return &authz.Response{
		Decision: authz.Deny,
		Reason:   "Permission denied",
	}
}

// Middleware creates an HTTP middleware for authorization
func (a *Authorizer) Middleware(permission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get the logger from the request context
			ctx := r.Context()
			logger := logging.LoggerFromContext(ctx)
			if logger == nil {
				logger = a.logger
			}

			// Get the identity from the context
			identity := auth.IdentityFromContext(ctx)
			if identity == nil {
				logger.Debug("Authorization failed: no identity in context")
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Create authorization request
			authzReq := &authz.Request{
				Identity:   identity,
				Permission: permission,
				Context:    ctx, // Ensure we pass the request context for cancellation
			}

			// Check authorization
			response := a.Authorize(authzReq)

			// Handle the response
			switch response.Decision {
			case authz.Allow:
				logger.Debug("Authorization successful",
					"subject", identity.Subject,
					"permission", permission,
				)
				next.ServeHTTP(w, r)
			case authz.Deny:
				logger.Info("Authorization failed: permission denied",
					"subject", identity.Subject,
					"permission", permission,
				)
				http.Error(w, "Forbidden", http.StatusForbidden)
			case authz.Unauthorized:
				logger.Info("Authorization failed: unauthorized")
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
			case authz.Error:
				logger.Error("Authorization failed: error", logging.Err(response.Error))
				// Use HTTP 503 Service Unavailable for SpiceDB errors to match original code
				http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
			}
		})
	}
}
