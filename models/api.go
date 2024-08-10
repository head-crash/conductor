package models

import (
	"time"
)

type TokenResponse struct {
	TokenType string    `json:"token_type"`
	Expires   time.Time `json:"expires_in"`
}
type TokenResponseBody struct {
	*TokenResponse
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type RenewTokenRequestBody struct {
	*TokenResponse
	AccessToken string `json:"access_token"`
}

type CreateUserRequestBody struct {
	Password string `json:"password"`
	Email    string `json:"email"`
}

type CreateClientRequestBody struct {
	Secret      string `json:"secret"`
	RedirectUrl string `json:"redirect_url"`
}

type CreateClientResponseBody struct {
	ClientId    string `json:"client_id"`
	RedirectUrl string `json:"redirect_url"`
}

type UserAccountOutput struct {
	Uuid  string `json:"uuid"`
	Email string `json:"email"`
	Role  Role   `json:"role"`
}

type ClientOutput struct {
	Id          string `json:"client_id"`
	RedirectUrl string `json:"redirect_url"`
}
