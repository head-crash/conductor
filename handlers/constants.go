package handlers

// ErrorMessage represents a type for error messages.
type ErrorMessage string

const (
	// ERR_CLIENT_ID is the error message for an invalid client ID.
	ERR_CLIENT_ID ErrorMessage = "Invalid clientId!"
	// ERR_CREDENTIALS is the error message for invalid email or password.
	ERR_CREDENTIALS ErrorMessage = "Invalid email or password!"
)

// TokenType represents a type for token types.
type TokenType string

const (
	// ACCESS_TOKEN is the token type for access tokens.
	ACCESS_TOKEN TokenType = "access"
	// REFRESH_TOKEN is the token type for refresh tokens.
	REFRESH_TOKEN TokenType = "refresh"
)
