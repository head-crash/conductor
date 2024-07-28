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
