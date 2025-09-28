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

	// Register custom auth endpoint on serve event
	app.OnServe().BindFunc(func(e *core.ServeEvent) error {
		e.Router.POST("/api/auth/pomerium", func(re *core.RequestEvent) error {
			return handlePomeriumAuth(app, re, config)
		}).Bind(apis.SkipSuccessActivityLog())
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
		mathrand.Seed(time.Now().UnixNano())
		return fmt.Sprintf("jwt-fallback-password-%d-%d-%d", os.Getpid(), time.Now().UnixNano(), mathrand.Int63())
	}
	// Convert to hex string (64 characters long)
	return hex.EncodeToString(bytes)
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

	// Check _pomerium cookie if no header found
	if token == "" {
		cookie, err := e.Request.Cookie("_pomerium")
		if err == nil {
			token = cookie.Value
		}
	}

	// If no Pomerium-specific JWT sources found, require authentication
	if token == "" {
		if config.Debug {
			log.Printf("🚫 No valid superuser auth and no Pomerium JWT found")
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
		return fmt.Errorf("failed to find or create user: %w", err)
	}

	// Set the authenticated user context so PocketBase treats this as an authenticated user
	reqInfo, infoErr := e.RequestInfo()
	if infoErr != nil {
		return fmt.Errorf("failed to get request info: %w", infoErr)
	}

	// Set the authenticated record in the request context
	reqInfo.Auth = user

	if config.Debug {
		log.Printf("✅ User authenticated via JWT: %s (%s)", user.GetString("display_name"), user.Id)
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

	// First, try to find existing user by JWT ID
	record, err := app.FindFirstRecordByData(collection, "jwt_id", userID)
	if err == nil {
		// User exists with this JWT ID, update their info and return
		log.Printf("Found existing user with JWT ID: %s", userID)
		updateUserRecord(record, claims)
		if err := app.Save(record); err != nil {
			return nil, fmt.Errorf("failed to update user record: %v", err)
		}
		return record, nil
	}

	// Second, try to find existing user by email (in case they exist but don't have jwt_id set)
	if claims.Email != "" {
		record, err = app.FindFirstRecordByData(collection, "email", claims.Email)
		if err == nil {
			// User exists with this email, update their JWT ID and other info
			log.Printf("Found existing user with email: %s, updating JWT ID to: %s", claims.Email, userID)
			record.Set("jwt_id", userID) // Link this JWT ID to the existing user
			updateUserRecord(record, claims)
			if err := app.Save(record); err != nil {
				return nil, fmt.Errorf("failed to update user record: %v", err)
			}
			return record, nil
		}
	}

	// User doesn't exist by JWT ID or email, create new one
	log.Printf("Creating new user with JWT ID: %s, email: %s", userID, claims.Email)
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

	// Set a cryptographically secure random password since these users authenticate via JWT/Pomerium
	// This password will never be used for authentication but must be unguessable for security
	securePassword := generateSecurePassword()
	record.Set("password", securePassword)
	record.Set("passwordConfirm", securePassword)
	
	// Set email visibility to true so emails are accessible
	record.Set("emailVisibility", true)
	
	// Set verified to true since users are already verified by Pomerium
	record.Set("verified", true)

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
