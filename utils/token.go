package utils

import (
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/fastjack-it/conductor/config"
)

func GenerateToken(clientID, tokenType string, expiresIn int64) (string, error) {
	claims := &jwt.StandardClaims{
		ExpiresAt: time.Now().Add(time.Duration(expiresIn) * time.Second).Unix(),
		Subject:   clientID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(config.SecretKey))
}
