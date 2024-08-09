package models

import (
	"time"
)

type TokenResponseBody struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	RefreshToken string    `json:"refresh_token"`
	Expires      time.Time `json:"expires_in"`
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
