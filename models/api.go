package models

import (
	"time"
)

// TokenResponse represents the response containing token type and expiration time.
type TokenResponse struct {
	TokenType string    `json:"token_type"` // TokenType is the type of the token.
	Expires   time.Time `json:"expires_in"` // Expires is the expiration time of the token.
}

// TokenResponseBody represents the response body containing tokens and token response.
type TokenResponseBody struct {
	*TokenResponse
	AccessToken  string `json:"access_token"`  // AccessToken is the access token.
	RefreshToken string `json:"refresh_token"` // RefreshToken is the refresh token.
}

// RenewTokenRequestBody represents the request body for renewing a token.
type RenewTokenRequestBody struct {
	*TokenResponse
	AccessToken string `json:"access_token"` // AccessToken is the access token to be renewed.
}

// CreateUserRequestBody represents the request body for creating a new user.
type CreateUserRequestBody struct {
	Password string `json:"password"` // Password is the user's password.
	Email    string `json:"email"`    // Email is the user's email address.
}

// CreateClientRequestBody represents the request body for creating a new client.
type CreateClientRequestBody struct {
	Secret      string `json:"secret"`       // Secret is the client's secret.
	RedirectUrl string `json:"redirect_url"` // RedirectUrl is the client's redirect URL.
}

// CreateClientResponseBody represents the response body for creating a new client.
type CreateClientResponseBody struct {
	ClientId    string `json:"client_id"`    // ClientId is the ID of the client.
	RedirectUrl string `json:"redirect_url"` // RedirectUrl is the client's redirect URL.
}

// UserAccountOutput represents the output of a user account.
type UserAccountOutput struct {
	Uuid  string `json:"uuid"`  // Uuid is the unique identifier of the user.
	Email string `json:"email"` // Email is the user's email address.
	Role  Role   `json:"role"`  // Role is the user's role.
}

// ClientOutput represents the output of a client.
type ClientOutput struct {
	Id          string `json:"client_id"`    // Id is the client's ID.
	RedirectUrl string `json:"redirect_url"` // RedirectUrl is the client's redirect URL.
}

// SetUserPasswordRequestBody represents the request body for setting a user's password.
type SetUserPasswordRequestBody struct {
	Password string `json:"password"` // Password is the new password for the user.
}
