package utils

import (
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/fastjack-it/conductor/config"
)

func GenerateToken(userId, tokenType string, expiresIn int64) (string, error) {
	claims := &jwt.StandardClaims{
		ExpiresAt: time.Now().Add(time.Duration(expiresIn) * time.Second).Unix(),
		Subject:   userId,
		Issuer:    config.EndpointUrl,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(config.SecretKey))
}

func ValidateToken(tokenString string) (string, error) {
	if token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(config.SecretKey), nil
	}); err != nil {
		return "", err
	} else if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims["sub"].(string), nil
	} else {
		return "", nil
	}
}
