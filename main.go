package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

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

	// Register custom auth endpoint on serve event
	app.OnServe().BindFunc(func(e *core.ServeEvent) error {
		e.Router.POST("/api/auth/pomerium", func(re *core.RequestEvent) error {
			return handlePomeriumAuth(app, re, config)
		}).Bind(apis.SkipSuccessActivityLog())
		return e.Next()
	})

	// Add JWT processing hooks for protected collections
	app.OnRecordsListRequest("users").BindFunc(func(e *core.RecordsListRequestEvent) error {
		if err := processJWTClaims(app, e.RequestEvent, config); err != nil {
			return e.ForbiddenError("Unauthorized: "+err.Error(), nil)
		}
		return e.Next()
	})

	app.OnRecordViewRequest("users").BindFunc(func(e *core.RecordRequestEvent) error {
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

// handlePomeriumAuth handles the custom auth endpoint
func handlePomeriumAuth(app core.App, e *core.RequestEvent, config *Config) error {
	err := processJWTClaims(app, e, config)
	if err != nil {
		return e.BadRequestError("Authentication failed: "+err.Error(), nil)
	}

	return e.JSON(http.StatusOK, map[string]string{"message": "Authentication successful"})
}

// processJWTClaims extracts and processes JWT claims for authentication
func processJWTClaims(app core.App, e *core.RequestEvent, config *Config) error {
	// Get JWT token from Authorization header, X-Pomerium-Jwt-Assertion header, or _pomerium cookie
	var token string

	// Check Authorization header first (supports both "jwt_token" and "Bearer jwt_token" formats)
	auth := e.Request.Header.Get("Authorization")
	if auth != "" {
		if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
			// Extract token from "Bearer jwt_token" format
			token = strings.TrimSpace(auth[7:])
		} else {
			// Use as-is for direct JWT token format
			token = strings.TrimSpace(auth)
		}
	}

	// Check X-Pomerium-Jwt-Assertion header if no Authorization header
	if token == "" {
		token = e.Request.Header.Get("X-Pomerium-Jwt-Assertion")
	}

	// Check _pomerium cookie if no headers found
	if token == "" {
		cookie, err := e.Request.Cookie("_pomerium")
		if err == nil {
			token = cookie.Value
		}
	}

	if token == "" {
		return fmt.Errorf("no JWT token found in Authorization header, X-Pomerium-Jwt-Assertion header, or _pomerium cookie")
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
	_, err = findOrCreateUser(app, *claims)
	if err != nil {
		return fmt.Errorf("failed to find or create user: %w", err)
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

	// Try to find existing user by JWT ID
	record, err := app.FindFirstRecordByData(collection, "jwt_id", userID)
	if err == nil {
		// User exists, update their info and return
		log.Printf("Found existing user with JWT ID: %s", userID)
		updateUserRecord(record, claims)
		if err := app.Save(record); err != nil {
			return nil, fmt.Errorf("failed to update user record: %v", err)
		}
		return record, nil
	}

	// User doesn't exist, create new one
	log.Printf("Creating new user with JWT ID: %s", userID)
	record = core.NewRecord(collection)
	record.Set("jwt_id", userID)
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
	if claims.Email != "" {
		record.Set("email", claims.Email)
	}
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

	log.Printf("Updated user record: display_name=%s, username=%s", displayName, username)
}

// getDisplayName generates a display name from JWT claims
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
