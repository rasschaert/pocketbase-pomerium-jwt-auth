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
	Email     string `json:"email"`
	Name      string `json:"name"`
	Sub       string `json:"sub"`
	Aud       string `json:"aud"`
	Iss       string `json:"iss"`
	GivenName string `json:"given_name"`
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
		log.Printf("🔍 Processing JWT claims for users collection")
	}

	// Extract JWT from header
	jwtToken := c.Request().Header.Get(config.JWTHeader)
	if jwtToken == "" {
		if config.Debug {
			log.Printf("⚠️  No JWT token found in header: %s", config.JWTHeader)
		}
		return nil // No JWT, continue without authentication
	}

	if config.Debug {
		log.Printf("🔍 Found JWT token, extracting claims (no signature validation)")
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
	if claims.Email == "" {
		return nil, apis.NewBadRequestError("Email claim is required", nil)
	}

	collection, err := app.Dao().FindCollectionByNameOrId("users")
	if err != nil {
		return nil, err
	}

	// Try to find existing user by email
	record, err := app.Dao().FindFirstRecordByFilter(
		collection.Id,
		"email = {:email}",
		map[string]any{"email": claims.Email},
	)

	if err != nil {
		// User doesn't exist, create new one
		if config.Debug {
			log.Printf("👤 Creating new user: %s", claims.Email)
		}

		record = models.NewRecord(collection)
		record.Set("email", claims.Email)
		record.Set("name", getDisplayName(claims))
		record.Set("username", generateUsername(claims))
		record.Set("verified", true) // Trust Pomerium authentication

		// Set additional fields from JWT claims
		if claims.GivenName != "" {
			record.Set("given_name", claims.GivenName)
		}
		if claims.FamilyName != "" {
			record.Set("family_name", claims.FamilyName)
		}
		if claims.Sub != "" {
			record.Set("pomerium_sub", claims.Sub)
		}

		if err := app.Dao().SaveRecord(record); err != nil {
			return nil, err
		}

		if config.Debug {
			log.Printf("✅ User created successfully: %s (%s)", record.GetString("email"), record.Id)
		}
	} else {
		// User exists, optionally update info
		if config.Debug {
			log.Printf("👤 User exists: %s (%s)", record.GetString("email"), record.Id)
		}

		// Update name if it has changed
		if getDisplayName(claims) != record.GetString("name") {
			record.Set("name", getDisplayName(claims))
			if err := app.Dao().SaveRecord(record); err != nil {
				log.Printf("⚠️  Failed to update user name: %v", err)
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
	// Fall back to email prefix
	if emailParts := strings.Split(claims.Email, "@"); len(emailParts) > 0 {
		return emailParts[0]
	}
	return claims.Email
}

func generateUsername(claims *PomeriumClaims) string {
	if claims.Email != "" {
		// Use email prefix as username
		if emailParts := strings.Split(claims.Email, "@"); len(emailParts) > 0 {
			return strings.ToLower(emailParts[0])
		}
	}
	return "user"
}
