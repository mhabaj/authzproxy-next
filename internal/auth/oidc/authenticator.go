// internal/auth/oidc/authenticator.go
package oidc

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"authzproxy/internal/auth"
	"authzproxy/internal/observability/logging"
	"authzproxy/internal/observability/metrics"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Authenticator implements OIDC authentication
type Authenticator struct {
	logger          *logging.Logger
	metrics         *metrics.Collector
	enabled         bool
	provider        *oidc.Provider
	verifier        *oidc.IDTokenVerifier
	config          oauth2.Config
	cookieName      string
	cookieSecretKey []byte
	appCtx          context.Context
}

// Config holds OIDC authenticator configuration
type Config struct {
	// Enabled indicates whether OIDC authentication is enabled
	Enabled bool

	// Issuer is the OIDC issuer URL
	Issuer string

	// ClientID is the OIDC client ID
	ClientID string

	// ClientSecret is the OIDC client secret
	ClientSecret string

	// RedirectURL is the redirect URL for OIDC authentication
	RedirectURL string

	// Scopes is a list of OIDC scopes to request
	Scopes []string

	// CookieName is the name of the session cookie
	CookieName string

	// CookieSecret is the secret key for cookie encryption
	CookieSecret string
}

// SessionData holds the user's session information
type SessionData struct {
	Subject            string    `json:"subject"`
	AccessToken        string    `json:"access_token"`
	RefreshToken       string    `json:"refresh_token"`
	Expiry             time.Time `json:"expiry"`
	RefreshTokenExpiry time.Time `json:"refresh_token_expiry"`
}

// New creates a new OIDC authenticator
func New(config Config, logger *logging.Logger, metrics *metrics.Collector) (*Authenticator, error) {
	logger = logger.WithModule("auth.oidc")

	if !config.Enabled {
		return &Authenticator{
			logger:  logger,
			metrics: metrics,
			enabled: false,
		}, nil
	}

	// Basic validation
	if config.Issuer == "" {
		return nil, fmt.Errorf("OIDC authentication enabled but no issuer provided")
	}

	if config.ClientID == "" || config.ClientSecret == "" {
		return nil, fmt.Errorf("OIDC authentication enabled but clientID or clientSecret not provided")
	}

	if config.RedirectURL == "" {
		return nil, fmt.Errorf("OIDC authentication enabled but no redirect URL provided")
	}

	if config.CookieSecret == "" {
		return nil, fmt.Errorf("OIDC authentication enabled but no cookie secret provided")
	}

	// Create a default cookie name if not provided
	cookieName := config.CookieName
	if cookieName == "" {
		cookieName = "authzproxy_session"
	}

	// Secret key should be at least 32 bytes for AES-256
	if len(config.CookieSecret) < 32 {
		return nil, fmt.Errorf("OIDC cookie secret must be at least 32 bytes long")
	}

	// Create context for OIDC operations
	ctx := context.Background()

	// Initialize OIDC provider
	logger.Debug("Initializing OIDC provider", "issuer", config.Issuer)
	provider, err := oidc.NewProvider(ctx, config.Issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize OIDC provider: %w", err)
	}

	// Create OIDC config
	oidcConfig := &oidc.Config{
		ClientID: config.ClientID,
	}

	// Prepare scopes
	scopes := config.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}

	// Create authenticator
	auth := &Authenticator{
		logger:   logger,
		metrics:  metrics,
		enabled:  true,
		provider: provider,
		verifier: provider.Verifier(oidcConfig),
		config: oauth2.Config{
			ClientID:     config.ClientID,
			ClientSecret: config.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  config.RedirectURL,
			Scopes:       scopes,
		},
		cookieName:      cookieName,
		cookieSecretKey: []byte(config.CookieSecret),
		appCtx:          ctx,
	}

	return auth, nil
}

// Name returns the name of this authenticator
func (a *Authenticator) Name() string {
	return "oidc"
}

// GetMiddleware returns an http.Handler middleware that performs OIDC authentication
func (a *Authenticator) GetMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.enabled {
			next.ServeHTTP(w, r)
			return
		}

		// Get the logger from the request context
		ctx := r.Context()
		logger := logging.LoggerFromContext(ctx)
		if logger == nil {
			logger = a.logger
		}

		// Check if we already have an identity in the context
		if identity := auth.IdentityFromContext(ctx); identity != nil {
			logger.Debug("Skipping OIDC: identity already set", "subject", identity.Subject)
			next.ServeHTTP(w, r)
			return
		}

		logger.Debug("Start OIDC authentication", "path", r.URL.Path)

		// Extract the callback path from the redirect URL
		callbackPath := extractCallbackPath(a.config.RedirectURL)
		if r.URL.Path == callbackPath {
			// Handle the callback
			a.handleCallback(w, r)
			return
		}

		// Try to get the session from the cookie
		sessionData, err := a.getSessionCookie(r)
		if err != nil || sessionData == nil {
			logger.Debug("Session cookie not found or invalid, redirecting to OIDC provider")
			a.startAuthenticationFlow(w, r)
			return
		}

		// Check if the refresh token has expired
		if !sessionData.RefreshTokenExpiry.IsZero() && time.Now().After(sessionData.RefreshTokenExpiry) {
			logger.Info("Refresh token has expired, redirecting to re-authenticate", "subject", sessionData.Subject)
			a.clearSessionCookie(w)
			a.startAuthenticationFlow(w, r)
			return
		}

		// Check if the access token has expired
		if time.Now().After(sessionData.Expiry) {
			logger.Info("Access token expired, attempting to refresh", "subject", sessionData.Subject)

			// Try to refresh the token
			tokenSource := a.config.TokenSource(a.appCtx, &oauth2.Token{
				RefreshToken: sessionData.RefreshToken,
			})

			newToken, err := tokenSource.Token()
			if err != nil {
				logger.Error("Failed to refresh access token", logging.Err(err))
				a.clearSessionCookie(w)
				a.startAuthenticationFlow(w, r)
				return
			}

			// Update session data
			sessionData.AccessToken = newToken.AccessToken
			sessionData.Expiry = newToken.Expiry

			// Check if refresh token was rotated
			if newToken.RefreshToken != "" && newToken.RefreshToken != sessionData.RefreshToken {
				logger.Info("Refresh token rotated, updating session data")
				sessionData.RefreshToken = newToken.RefreshToken
			}

			// Try to update the refresh token expiry if provided
			if refreshExpiresIn := newToken.Extra("refresh_expires_in"); refreshExpiresIn != nil {
				logger.Info("Refresh token expiry received during refresh", "refresh_expires_in", refreshExpiresIn)
				expiresInSeconds, err := strconv.Atoi(fmt.Sprintf("%v", refreshExpiresIn))
				if err == nil {
					sessionData.RefreshTokenExpiry = time.Now().Add(time.Duration(expiresInSeconds) * time.Second)
				}
			}

			// Save the updated session
			if err := a.saveSessionCookie(w, *sessionData); err != nil {
				logger.Error("Failed to update session cookie", logging.Err(err))
				http.Error(w, "Failed to update session", http.StatusInternalServerError)
				return
			}

			logger.Info("Access token refreshed successfully", "subject", sessionData.Subject)
		}

		// Create identity
		identity := &auth.Identity{
			Subject:  sessionData.Subject,
			Provider: a.Name(),
			Attributes: map[string]interface{}{
				"access_token": sessionData.AccessToken,
			},
		}

		logger.Debug("OIDC authentication successful", "subject", sessionData.Subject)
		a.metrics.RecordAuthentication("oidc", true)

		// Add identity and auth type to request context
		ctx = auth.ContextWithIdentity(ctx, identity)
		ctx = auth.ContextWithAuthType(ctx, auth.AuthTypeOIDC)

		// Continue with the next handler
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// handleCallback handles the OIDC authentication callback
func (a *Authenticator) handleCallback(w http.ResponseWriter, r *http.Request) {
	// Get the logger from the request context
	ctx := r.Context()
	logger := logging.LoggerFromContext(ctx)
	if logger == nil {
		logger = a.logger
	}

	logger.Debug("Start OIDC callback handling")

	// Verify the state parameter to prevent CSRF attacks
	state := r.URL.Query().Get("state")
	if state == "" {
		logger.Error("No state parameter in callback")
		http.Error(w, "Invalid callback", http.StatusBadRequest)
		return
	}

	stateCookie, err := r.Cookie("oidc_state")
	if err != nil || stateCookie.Value != state {
		logger.Error("State mismatch or cookie missing",
			"cookie_exists", err == nil,
			"cookie_state", stateCookie.Value,
			"param_state", state)
		http.Error(w, "State mismatch", http.StatusBadRequest)
		return
	}

	// Get the code verifier from the cookie
	codeVerifierCookie, err := r.Cookie("oidc_code_verifier")
	if err != nil {
		logger.Error("No code verifier cookie", logging.Err(err))
		http.Error(w, "Code verifier not found", http.StatusBadRequest)
		return
	}

	// Get the origin URL from the cookie
	originURLCookie, err := r.Cookie("oidc_origin_url")
	if err != nil {
		logger.Error("No origin URL cookie", logging.Err(err))
		http.Error(w, "Origin URL not found", http.StatusBadRequest)
		return
	}

	// Get the code from the URL
	code := r.URL.Query().Get("code")
	if code == "" {
		logger.Error("No code parameter in callback")
		http.Error(w, "No code received", http.StatusBadRequest)
		return
	}

	// Exchange the code for tokens
	oauth2Token, err := a.config.Exchange(a.appCtx, code, oauth2.VerifierOption(codeVerifierCookie.Value))
	if err != nil {
		logger.Error("Failed to exchange token", logging.Err(err))
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		return
	}

	// Log token details for debugging
	extraFields := []string{"expires_in", "refresh_expires_in", "token_type", "scope", "id_token"}
	for _, field := range extraFields {
		value := oauth2Token.Extra(field)
		if value != nil {
			logger.Debug("Token extra field", "key", field, "value", value)
		}
	}

	// Extract the ID token
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		logger.Error("No ID token in OAuth2 token")
		http.Error(w, "No ID token in OAuth2 token", http.StatusInternalServerError)
		return
	}

	// Verify the ID token
	idToken, err := a.verifier.Verify(a.appCtx, rawIDToken)
	if err != nil {
		logger.Error("Failed to verify ID token", logging.Err(err))
		http.Error(w, "Failed to verify ID token", http.StatusInternalServerError)
		return
	}

	// Extract claims from the ID token
	var claims struct {
		Subject string `json:"sub"`
		Email   string `json:"email,omitempty"`
		Name    string `json:"name,omitempty"`
	}

	if err := idToken.Claims(&claims); err != nil {
		logger.Error("Failed to parse claims from ID token", logging.Err(err))
		http.Error(w, "Failed to parse claims", http.StatusInternalServerError)
		return
	}

	logger.Debug("OIDC claims extracted", "subject", claims.Subject)

	// Create session data
	sessionData := SessionData{
		Subject:      claims.Subject,
		AccessToken:  oauth2Token.AccessToken,
		RefreshToken: oauth2Token.RefreshToken,
		Expiry:       oauth2Token.Expiry,
	}

	// Set refresh token expiry if available
	if refreshExpiresIn := oauth2Token.Extra("refresh_expires_in"); refreshExpiresIn != nil {
		expiresInSeconds, err := strconv.Atoi(fmt.Sprintf("%v", refreshExpiresIn))
		if err == nil {
			sessionData.RefreshTokenExpiry = time.Now().Add(time.Duration(expiresInSeconds) * time.Second)
		} else {
			// Default expiry (30 minutes to match original)
			sessionData.RefreshTokenExpiry = time.Now().Add(30 * time.Minute)
		}
	} else {
		// Default expiry (30 minutes to match original)
		sessionData.RefreshTokenExpiry = time.Now().Add(30 * time.Minute)
	}

	// Save the session data in a cookie
	if err := a.saveSessionCookie(w, sessionData); err != nil {
		logger.Error("Failed to save session cookie", logging.Err(err))
		http.Error(w, "Failed to save session", http.StatusInternalServerError)
		return
	}

	logger.Info("Session cookie saved successfully", "subject", claims.Subject)
	a.metrics.RecordAuthentication("oidc", true)

	// Clear temporary cookies
	a.clearTempCookies(w)

	// Redirect to the original URL
	http.Redirect(w, r, originURLCookie.Value, http.StatusSeeOther)
}

// startAuthenticationFlow initiates the OIDC authentication flow
func (a *Authenticator) startAuthenticationFlow(w http.ResponseWriter, r *http.Request) {
	// Generate state and code verifier
	state, err := randomString(16)
	if err != nil {
		a.logger.Error("Failed to generate state parameter", logging.Err(err))
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	codeVerifier := oauth2.GenerateVerifier()

	// Store state and code verifier in cookies
	a.setTempCookie(w, r, "oidc_state", state)
	a.setTempCookie(w, r, "oidc_code_verifier", codeVerifier)
	a.setTempCookie(w, r, "oidc_origin_url", r.URL.String())

	// Generate authorization URL with PKCE
	authURL := a.config.AuthCodeURL(
		state,
		oauth2.S256ChallengeOption(codeVerifier),
	)

	a.logger.Info("Redirecting to OIDC provider for authentication")

	// Redirect to the authorization URL
	http.Redirect(w, r, authURL, http.StatusFound)
}

// setTempCookie sets a temporary cookie for the OIDC flow
func (a *Authenticator) setTempCookie(w http.ResponseWriter, r *http.Request, name, value string) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(10 * time.Minute.Seconds()),
	}
	http.SetCookie(w, cookie)
}

// clearTempCookies clears temporary cookies used in the OIDC flow
func (a *Authenticator) clearTempCookies(w http.ResponseWriter) {
	cookies := []string{"oidc_state", "oidc_code_verifier", "oidc_origin_url"}
	for _, name := range cookies {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
			MaxAge:   -1,
		})
	}
}

// getSessionCookie retrieves and decrypts the session data from a cookie
func (a *Authenticator) getSessionCookie(r *http.Request) (*SessionData, error) {
	cookie, err := r.Cookie(a.cookieName)
	if err != nil {
		return nil, err
	}

	// Decrypt the cookie value
	encrypted, err := base64.URLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to decode session cookie: %w", err)
	}

	// Create cipher block
	block, err := aes.NewCipher(a.cookieSecretKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Get nonce size
	nonceSize := gcm.NonceSize()
	if len(encrypted) < nonceSize {
		return nil, fmt.Errorf("encrypted data too short")
	}

	// Extract nonce and ciphertext
	nonce, ciphertext := encrypted[:nonceSize], encrypted[nonceSize:]

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt session data: %w", err)
	}

	// Unmarshal the session data
	var sessionData SessionData
	if err := json.Unmarshal(plaintext, &sessionData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session data: %w", err)
	}

	return &sessionData, nil
}

// saveSessionCookie encrypts and saves the session data in a cookie
func (a *Authenticator) saveSessionCookie(w http.ResponseWriter, sessionData SessionData) error {
	// Marshal the session data
	plaintext, err := json.Marshal(sessionData)
	if err != nil {
		return fmt.Errorf("failed to marshal session data: %w", err)
	}

	// Create cipher block
	block, err := aes.NewCipher(a.cookieSecretKey)
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	// Create nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	// Encode
	encoded := base64.URLEncoding.EncodeToString(ciphertext)

	// Set cookie expiry time (30 minutes default to match original code)
	var maxAge int
	if !sessionData.RefreshTokenExpiry.IsZero() {
		maxAge = int(time.Until(sessionData.RefreshTokenExpiry).Seconds())
	} else {
		maxAge = int(30 * time.Minute.Seconds()) // 30 minutes as in original
	}

	// Ensure the cookie expiration is positive
	if maxAge <= 0 {
		return fmt.Errorf("invalid cookie expiration time")
	}

	// Create cookie
	cookie := &http.Cookie{
		Name:     a.cookieName,
		Value:    encoded,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	}

	http.SetCookie(w, cookie)
	return nil
}

// clearSessionCookie clears the session cookie
func (a *Authenticator) clearSessionCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     a.cookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
	}
	http.SetCookie(w, cookie)
	a.logger.Debug("Session cookie cleared")
}

// extractCallbackPath extracts the path component from a URL
func extractCallbackPath(urlStr string) string {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return "/callback"
	}
	if parsedURL.Path == "" {
		return "/callback"
	}
	return parsedURL.Path
}

// randomString generates a random string of the specified length
func randomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}
