package handlers

import (
	"net/http"
	"time"

	p "github.com/fastjack-it/conductor/persistence"
	"github.com/fastjack-it/conductor/utils"
	"github.com/gin-gonic/gin"
)

type TokenResponse struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	RefreshToken string    `json:"refresh_token"`
	Expires      time.Time `json:"expires_in"`
}

func TokenHandler(c *gin.Context) {
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")

	client, err := p.Db.GetClientById(clientID)
	if err != nil || clientID != client.ClientId || clientSecret != client.Secret {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid client credentials"})
		return
	}

	accessToken, err := utils.GenerateToken(clientID, "access", 3600)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate access token"})
		return
	}

	refreshToken, err := utils.GenerateToken(clientID, "refresh", 7200)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate refresh token"})
		return
	}

	response := TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "bearer",
		RefreshToken: refreshToken,
		Expires:      time.Now().Add(time.Second * 3600),
	}

	c.JSON(http.StatusOK, response)
}

func AuthorizeHandler(c *gin.Context) {
	// Handle OAuth authorize endpoint logic here
	// For simplicity, this example does not include implementation details
	c.JSON(http.StatusOK, gin.H{"message": "Authorize endpoint"})
}
