package main

import (
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	mathrand "math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
)

// PomeriumClaims represents the JWT payload from Pomerium
type PomeriumClaims struct {
	Email      string `json:"email"`
	Name       string `json:"name"`
	Sub        string `json:"sub"`
	Oid        string `json:"oid"`    // Object ID - primary unique identifier
	IdpId      string `json:"idp_id"` // Identity Provider ID
	Aud        string `json:"aud"`
	Iss        string `json:"iss"`
	GivenName  string `json:"given_name"`
	FamilyName string `json:"family_name"`
}

// Config holds our configuration
type Config struct {
	JWTHeader string
	Debug     bool
}

func main() {
	app := pocketbase.New()

	// Load configuration
	config := loadConfig()

	if config.Debug {
		log.Printf("🔧 PocketBase JWT Trust Mode (No Signature Validation)")
		log.Printf("  Header: %s", config.JWTHeader)
		log.Printf("  Debug: %t", config.Debug)
	}

	// Register custom endpoints on serve event (using /api/pomerium to avoid collision with system /api/auth routes)
	app.OnServe().BindFunc(func(e *core.ServeEvent) error {
		// Register POST endpoint for Pomerium auth
		e.Router.POST("/api/pomerium/auth", func(re *core.RequestEvent) error {
			if config.Debug {
				log.Printf("🔗 POST /api/pomerium/auth called")
			}
			return handlePomeriumAuth(app, re, config)
		})

		// Register GET endpoint for current user info
		e.Router.GET("/api/pomerium/me", func(re *core.RequestEvent) error {
			if config.Debug {
				log.Printf("🔗 GET /api/pomerium/me called")
			}
			return handleGetCurrentUser(app, re, config)
		})

		// Always log endpoint registration (not just in debug mode)
		log.Printf("✅ Registered custom endpoints:")
		log.Printf("  POST /api/pomerium/auth")
		log.Printf("  GET  /api/pomerium/me")

		return e.Next()
	})

	// Add JWT processing hooks for ALL collections (protect everything)
	app.OnRecordsListRequest().BindFunc(func(e *core.RecordsListRequestEvent) error {
		if err := processJWTClaims(app, e.RequestEvent, config); err != nil {
			return e.ForbiddenError("Unauthorized: "+err.Error(), nil)
		}
		return e.Next()
	})

	app.OnRecordViewRequest().BindFunc(func(e *core.RecordRequestEvent) error {
		if err := processJWTClaims(app, e.RequestEvent, config); err != nil {
			return e.ForbiddenError("Unauthorized: "+err.Error(), nil)
		}
		return e.Next()
	})

	app.OnRecordCreateRequest().BindFunc(func(e *core.RecordRequestEvent) error {
		if err := processJWTClaims(app, e.RequestEvent, config); err != nil {
			return e.ForbiddenError("Unauthorized: "+err.Error(), nil)
		}
		return e.Next()
	})

	app.OnRecordUpdateRequest().BindFunc(func(e *core.RecordRequestEvent) error {
		if err := processJWTClaims(app, e.RequestEvent, config); err != nil {
			return e.ForbiddenError("Unauthorized: "+err.Error(), nil)
		}
		return e.Next()
	})

	app.OnRecordDeleteRequest().BindFunc(func(e *core.RecordRequestEvent) error {
		if err := processJWTClaims(app, e.RequestEvent, config); err != nil {
			return e.ForbiddenError("Unauthorized: "+err.Error(), nil)
		}
		return e.Next()
	})

	if err := app.Start(); err != nil {
		log.Fatal(err)
	}
}

func loadConfig() *Config {
	debug := os.Getenv("DEBUG") == "true"

	return &Config{
		JWTHeader: getEnvOrDefault("JWT_HEADER", "X-Pomerium-Jwt-Assertion"),
		Debug:     debug,
	}
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// generateSecurePassword creates a cryptographically secure random password
func generateSecurePassword() string {
	// Generate 32 random bytes (256 bits)
	bytes := make([]byte, 32)
	if _, err := cryptorand.Read(bytes); err != nil {
		// Fallback to a timestamp-based password if crypto/rand fails
		rng := mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
		return fmt.Sprintf("jwt-fallback-password-%d-%d-%d", os.Getpid(), time.Now().UnixNano(), rng.Int63())
	}
	// Convert to hex string (64 characters long)
	return hex.EncodeToString(bytes)
}

// handlePomeriumAuth handles the custom auth endpoint
func handlePomeriumAuth(app core.App, e *core.RequestEvent, config *Config) error {
	err := processJWTClaims(app, e, config)
	if err != nil {
		return apis.NewBadRequestError("Authentication failed: "+err.Error(), nil)
	}

	return e.JSON(http.StatusOK, map[string]string{"message": "Authentication successful"})
}

// handleGetCurrentUser returns information about the currently authenticated user
func handleGetCurrentUser(app core.App, e *core.RequestEvent, config *Config) error {
	// Process JWT claims to set user context
	err := processJWTClaims(app, e, config)
	if err != nil {
		return apis.NewUnauthorizedError("Authentication required: "+err.Error(), nil)
	}

	// Get the authenticated user from request context
	var user *core.Record

	// First try to get from our stored context
	if storedAuth := e.Get("auth"); storedAuth != nil {
		if authRecord, ok := storedAuth.(*core.Record); ok {
			user = authRecord
		}
	}

	// Fallback to RequestInfo if not found in stored context
	if user == nil {
		requestInfo, err := e.RequestInfo()
		if err != nil {
			return apis.NewInternalServerError("Failed to get request info", err)
		}
		user = requestInfo.Auth
	}

	if user == nil {
		if config.Debug {
			log.Printf("❌ No authenticated user found in request context")
		}
		return apis.NewUnauthorizedError("No authenticated user found", nil)
	}

	// Return user information
	userInfo := map[string]interface{}{
		"id":           user.Id,
		"email":        user.GetString("email"),
		"display_name": user.GetString("display_name"),
		"username":     user.GetString("username"),
		"verified":     user.GetBool("verified"),
	}

	if config.Debug {
		log.Printf("🔍 Current user info requested: %s (%s)", user.GetString("display_name"), user.GetString("email"))
	}

	return e.JSON(http.StatusOK, map[string]interface{}{
		"user":          userInfo,
		"authenticated": true,
	})
}

// processJWTClaims extracts and processes JWT claims for authentication
func processJWTClaims(app core.App, e *core.RequestEvent, config *Config) error {
	// First, check if there's already valid superuser authentication
	requestInfo, err := e.RequestInfo()
	if err == nil && requestInfo.HasSuperuserAuth() {
		if config.Debug {
			log.Printf("✅ Valid superuser authentication found, allowing request")
		}
		return nil // Superuser is already authenticated, no need for JWT processing
	}

	// Look for Pomerium JWT sources
	var token string

	// Check X-Pomerium-Jwt-Assertion header first (most specific)
	token = e.Request.Header.Get("X-Pomerium-Jwt-Assertion")
	if config.Debug && token != "" {
		log.Printf("🔑 Found JWT in X-Pomerium-Jwt-Assertion header")
	}

	// Check _pomerium cookie if no header found
	if token == "" {
		cookie, err := e.Request.Cookie("_pomerium")
		if err == nil {
			token = cookie.Value
			if config.Debug {
				log.Printf("🔑 Found JWT in _pomerium cookie")
			}
		}
	}

	// If no Pomerium-specific JWT sources found, require authentication
	if token == "" {
		if config.Debug {
			log.Printf("🚫 No valid superuser auth and no Pomerium JWT found")
			log.Printf("   Headers: %+v", e.Request.Header)
			log.Printf("   Cookies: %+v", e.Request.Cookies())
		}
		return fmt.Errorf("authentication required: provide either valid superuser credentials or Pomerium JWT via X-Pomerium-Jwt-Assertion header or _pomerium cookie")
	}

	// Extract JWT claims (without signature validation)
	claims, err := extractJWTClaims(token)
	if err != nil {
		return fmt.Errorf("failed to extract JWT claims: %w", err)
	}

	if config.Debug {
		log.Printf("🎫 JWT Claims: %+v", claims)
	}

	// Find or create user based on JWT claims
	user, err := findOrCreateUser(app, *claims)
	if err != nil {
		if config.Debug {
			log.Printf("❌ Failed to find or create user: %v", err)
		}
		return fmt.Errorf("failed to find or create user: %w", err)
	}

	// Set the authenticated user context so PocketBase treats this as an authenticated user
	// Store the user in the request context for later retrieval
	e.Set("auth", user)

	// Also try to set it in RequestInfo for PocketBase compatibility
	reqInfo, infoErr := e.RequestInfo()
	if infoErr == nil {
		reqInfo.Auth = user
	}

	if config.Debug {
		log.Printf("✅ User authenticated via JWT: %s (%s)", user.GetString("display_name"), user.Id)
		log.Printf("   User ID: %s", user.Id)
		log.Printf("   Email: %s", user.GetString("email"))
	}

	return nil
}

// extractJWTClaims extracts the payload from JWT without signature verification
func extractJWTClaims(tokenString string) (*PomeriumClaims, error) {
	// Split JWT into parts (header.payload.signature)
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	// Decode payload (second part)
	payload := parts[1]

	// Add padding if needed for base64 decoding
	if m := len(payload) % 4; m != 0 {
		payload += strings.Repeat("=", 4-m)
	}

	// Decode base64
	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	// Parse JSON claims
	var claims PomeriumClaims
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	return &claims, nil
}

// findOrCreateUser finds an existing user or creates a new one based on JWT claims
func findOrCreateUser(app core.App, claims PomeriumClaims) (*core.Record, error) {
	collection, err := app.FindCollectionByNameOrId("users")
	if err != nil {
		return nil, fmt.Errorf("users collection not found: %v", err)
	}

	// Use JWT ID (oid or sub) as the primary identifier for finding users
	var userID string
	if claims.Oid != "" {
		userID = claims.Oid
	} else if claims.Sub != "" {
		userID = claims.Sub
	} else {
		return nil, fmt.Errorf("no user identifier found in JWT claims (oid or sub)")
	}

	// Remove dashes and truncate to 15 characters for PocketBase ID limits
	originalID := userID
	userID = strings.ReplaceAll(userID, "-", "")
	if len(userID) > 15 {
		userID = userID[:15]
	}

	if originalID != userID {
		log.Printf("Processed JWT ID: %s -> %s (removed dashes, truncated to 15 chars)", originalID, userID)
	}

	// First, try to find existing user by ID (using the JWT oid directly as the record ID)
	record, err := app.FindRecordById(collection, userID)
	if err == nil {
		// User exists with this ID, update their info and return
		log.Printf("Found existing user with ID: %s", userID)
		updateUserRecord(record, claims)
		if err := app.Save(record); err != nil {
			return nil, fmt.Errorf("failed to update user record: %v", err)
		}
		return record, nil
	}

	// Second, try to find existing user by email (in case they exist but have a different ID)
	if claims.Email != "" {
		record, err = app.FindFirstRecordByData(collection, "email", claims.Email)
		if err == nil {
			// User exists with this email but different ID - this is a conflict
			// We'll keep the existing record but log a warning
			log.Printf("Warning: Found existing user with email %s but different ID. Existing ID: %s, JWT ID: %s", claims.Email, record.Id, userID)
			updateUserRecord(record, claims)
			if err := app.Save(record); err != nil {
				return nil, fmt.Errorf("failed to update user record: %v", err)
			}
			return record, nil
		}
	}

	// User doesn't exist, create new one with explicit ID from JWT
	log.Printf("Creating new user with ID: %s, email: %s", userID, claims.Email)
	record = core.NewRecord(collection)
	record.Set("id", userID) // Set the record ID to the JWT oid
	updateUserRecord(record, claims)

	if err := app.Save(record); err != nil {
		return nil, fmt.Errorf("failed to create user record: %v", err)
	}

	return record, nil
}

// updateUserRecord updates a user record with JWT claims data
func updateUserRecord(record *core.Record, claims PomeriumClaims) {
	// Update user record with JWT claims
	if claims.Name != "" {
		record.Set("name", claims.Name)
	}

	// Set email - use a default if not provided in JWT
	email := claims.Email
	if email == "" {
		// Generate a placeholder email based on JWT ID if no email is provided
		var userID string
		if claims.Oid != "" {
			userID = claims.Oid
		} else if claims.Sub != "" {
			userID = claims.Sub
		} else {
			userID = "unknown"
		}
		email = fmt.Sprintf("%s@pomerium-user.local", userID)
	}
	record.Set("email", email)

	if claims.GivenName != "" {
		record.Set("given_name", claims.GivenName)
	}
	if claims.FamilyName != "" {
		record.Set("family_name", claims.FamilyName)
	}

	// Set a display name (fallback hierarchy: name -> given+family -> email -> jwt_id)
	displayName := getDisplayName(claims)
	record.Set("display_name", displayName)

	// Set username (fallback hierarchy: preferred_username -> email -> jwt_id)
	username := getUsername(claims)
	record.Set("username", username)

	// Set a cryptographically secure random password since these users authenticate via JWT/Pomerium
	// This password will never be used for authentication but must be unguessable for security
	securePassword := generateSecurePassword()
	record.Set("password", securePassword)
	record.Set("passwordConfirm", securePassword)

	// Set email visibility to true so emails are accessible
	record.Set("emailVisibility", true)

	// Set verified to true since users are already verified by Pomerium
	record.Set("verified", true)

	log.Printf("Updated user record: display_name=%s, username=%s, email=%s", displayName, username, email)
} // getDisplayName generates a display name from JWT claims
func getDisplayName(claims PomeriumClaims) string {
	if claims.Name != "" {
		return claims.Name
	}
	if claims.GivenName != "" && claims.FamilyName != "" {
		return claims.GivenName + " " + claims.FamilyName
	}
	if claims.GivenName != "" {
		return claims.GivenName
	}
	if claims.Email != "" {
		return claims.Email
	}
	if claims.Oid != "" {
		return "User " + claims.Oid
	}
	if claims.Sub != "" {
		return "User " + claims.Sub
	}
	return "Anonymous User"
}

// getUsername generates a username from JWT claims
func getUsername(claims PomeriumClaims) string {
	if claims.Email != "" {
		// Use email prefix as username
		if emailParts := strings.Split(claims.Email, "@"); len(emailParts) > 0 {
			return strings.ToLower(emailParts[0])
		}
	}
	if claims.Oid != "" {
		return "user_" + claims.Oid
	}
	if claims.Sub != "" {
		return "user_" + claims.Sub
	}
	return "anonymous_user"
}
