package main

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"os"
	"strings"

	"github.com/labstack/echo/v5"
	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/models"
)

// PomeriumClaims represents the JWT payload from Pomerium (no signature validation needed)
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

// Config holds our simplified configuration
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

	// Use PocketBase hooks for JWT claim processing
	app.OnRecordsListRequest().Add(func(e *core.RecordsListEvent) error {
		if e.Collection.Name != "users" {
			return nil
		}

		c := e.HttpContext
		return processJWTClaims(c, app, config)
	})

	app.OnRecordViewRequest().Add(func(e *core.RecordViewEvent) error {
		if e.Collection.Name != "users" {
			return nil
		}

		c := e.HttpContext
		return processJWTClaims(c, app, config)
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

// processJWTClaims extracts claims from JWT without signature validation
func processJWTClaims(c echo.Context, app *pocketbase.PocketBase, config *Config) error {
	if config.Debug {
		log.Printf("🔍 Processing authentication for users collection")
	}

	// Extract JWT from header first
	jwtToken := c.Request().Header.Get(config.JWTHeader)

	// If no JWT in header, check for _pomerium cookie
	if jwtToken == "" {
		if cookie, err := c.Request().Cookie("_pomerium"); err == nil {
			jwtToken = cookie.Value
			if config.Debug {
				log.Printf("✅ Found JWT token in _pomerium cookie")
			}
		}
	}

	// If no JWT token found in header or cookie, check for Authorization header
	if jwtToken == "" {
		authHeader := c.Request().Header.Get("Authorization")

		// Always log for debugging (remove later)
		log.Printf("🔍 DEBUG: JWT='%s', AuthHeader='%s'", jwtToken, authHeader)

		if authHeader == "" {
			if config.Debug {
				log.Printf("❌ No JWT token in header '%s' and no Authorization header found", config.JWTHeader)
			}
			return apis.NewUnauthorizedError("Authentication required: provide either JWT header or Authorization Bearer token", nil)
		}

		log.Printf("✅ Found Authorization header, checking if it's a valid PocketBase token")
		if config.Debug {
			log.Printf("🔍 Authorization header content: %s", authHeader[:20]+"...")
		}

		// Validate it's a valid PocketBase auth token (admin or user)
		requestInfo := apis.RequestInfo(c)
		authRecord := requestInfo.AuthRecord
		admin := requestInfo.Admin

		// Always log for debugging
		log.Printf("🔍 DEBUG: AuthRecord=%v, Admin=%v", authRecord != nil, admin != nil)

		if authRecord == nil && admin == nil {
			log.Printf("❌ Authorization header is not a valid PocketBase authentication token")
			return apis.NewUnauthorizedError("Invalid authentication token", nil)
		}

		if config.Debug {
			if authRecord != nil {
				log.Printf("✅ Valid user authentication: %s", authRecord.GetString("email"))
			} else {
				log.Printf("✅ Valid admin authentication")
			}
		}

		// Valid PocketBase authentication - no need to process JWT claims
		return nil
	}

	if config.Debug {
		log.Printf("✅ Found JWT token in header '%s', extracting claims (no signature validation)", config.JWTHeader)
	}

	// Extract claims from JWT payload (no validation)
	claims, err := extractJWTClaims(jwtToken)
	if err != nil {
		log.Printf("❌ Failed to extract JWT claims: %v", err)
		return apis.NewBadRequestError("Invalid JWT format", err)
	}

	if config.Debug {
		log.Printf("✅ JWT claims extracted successfully")
		log.Printf("👤 User: %s (%s)", claims.Email, claims.Name)
	}

	// Create or update user based on JWT claims
	user, err := findOrCreateUser(app, claims, config)
	if err != nil {
		log.Printf("❌ Failed to create/update user: %v", err)
		return apis.NewBadRequestError("Failed to process user", err)
	}

	if config.Debug {
		log.Printf("👤 User processed: %s (%s)", user.GetString("email"), user.Id)
	}

	return nil
}

// extractJWTClaims extracts the payload from JWT without signature verification
func extractJWTClaims(tokenString string) (*PomeriumClaims, error) {
	// Split JWT into parts (header.payload.signature)
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, apis.NewBadRequestError("Invalid JWT format", nil)
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
		return nil, err
	}

	// Parse JSON claims
	var claims PomeriumClaims
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return nil, err
	}

	return &claims, nil
}

// findOrCreateUser finds an existing user or creates a new one based on JWT claims
func findOrCreateUser(app *pocketbase.PocketBase, claims *PomeriumClaims, config *Config) (*models.Record, error) {
	// Determine unique identifier - prefer oid, fallback to sub
	var uniqueId string
	var idField string

	if claims.Oid != "" {
		uniqueId = claims.Oid
		idField = "pomerium_oid"
	} else if claims.Sub != "" {
		uniqueId = claims.Sub
		idField = "pomerium_sub"
	} else {
		return nil, apis.NewBadRequestError("No unique identifier found in JWT (oid or sub required)", nil)
	}

	collection, err := app.Dao().FindCollectionByNameOrId("users")
	if err != nil {
		return nil, err
	}

	// Try to find existing user by Pomerium ID (oid or sub)
	record, err := app.Dao().FindFirstRecordByFilter(
		collection.Id,
		idField+" = {:id}",
		map[string]any{"id": uniqueId},
	)

	if err != nil {
		// User doesn't exist, create new one
		if config.Debug {
			log.Printf("👤 Creating new user with %s: %s", idField, uniqueId)
		}

		record = models.NewRecord(collection)

		// Set core fields
		record.Set("name", getDisplayName(claims))
		record.Set("username", generateUsername(claims))
		record.Set("verified", true) // Trust Pomerium authentication

		// Set email if available
		if claims.Email != "" {
			record.Set("email", claims.Email)
		}

		// Store Pomerium identifiers for future lookups
		if claims.Oid != "" {
			record.Set("pomerium_oid", claims.Oid)
		}
		if claims.Sub != "" {
			record.Set("pomerium_sub", claims.Sub)
		}
		if claims.IdpId != "" {
			record.Set("pomerium_idp_id", claims.IdpId)
		}

		// Set additional fields from JWT claims
		if claims.GivenName != "" {
			record.Set("given_name", claims.GivenName)
		}
		if claims.FamilyName != "" {
			record.Set("family_name", claims.FamilyName)
		}

		if err := app.Dao().SaveRecord(record); err != nil {
			return nil, err
		}

		if config.Debug {
			emailInfo := "no email"
			if claims.Email != "" {
				emailInfo = claims.Email
			}
			log.Printf("✅ User created successfully: %s (%s) [%s]", emailInfo, record.Id, uniqueId)
		}
	} else {
		// User exists, optionally update info
		if config.Debug {
			log.Printf("👤 User exists: %s (%s)", record.GetString("name"), record.Id)
		}

		// Update name and email if they have changed
		needsUpdate := false

		if displayName := getDisplayName(claims); displayName != record.GetString("name") {
			record.Set("name", displayName)
			needsUpdate = true
		}

		if claims.Email != "" && claims.Email != record.GetString("email") {
			record.Set("email", claims.Email)
			needsUpdate = true
		}

		if needsUpdate {
			if err := app.Dao().SaveRecord(record); err != nil {
				log.Printf("⚠️  Failed to update user info: %v", err)
			}
		}
	}

	return record, nil
}

func getDisplayName(claims *PomeriumClaims) string {
	if claims.Name != "" {
		return claims.Name
	}
	if claims.GivenName != "" && claims.FamilyName != "" {
		return claims.GivenName + " " + claims.FamilyName
	}
	if claims.GivenName != "" {
		return claims.GivenName
	}
	// Fall back to email prefix if available
	if claims.Email != "" {
		if emailParts := strings.Split(claims.Email, "@"); len(emailParts) > 0 {
			return emailParts[0]
		}
		return claims.Email
	}
	// Final fallback to user ID
	if claims.Oid != "" {
		return "User " + claims.Oid[:8] // Show first 8 chars of OID
	}
	if claims.Sub != "" {
		return "User " + claims.Sub[:8] // Show first 8 chars of Sub
	}
	return "Anonymous User"
}

func generateUsername(claims *PomeriumClaims) string {
	if claims.Email != "" {
		// Use email prefix as username
		if emailParts := strings.Split(claims.Email, "@"); len(emailParts) > 0 {
			return strings.ToLower(emailParts[0])
		}
	}
	// Generate username from ID if no email
	if claims.Oid != "" {
		return "user_" + strings.ToLower(claims.Oid[:8])
	}
	if claims.Sub != "" {
		return "user_" + strings.ToLower(claims.Sub[:8])
	}
	return "anonymous_user"
}
