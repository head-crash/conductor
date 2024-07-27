package handlers

import (
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/fastjack-it/conductor/config"
	"github.com/fastjack-it/conductor/models"
	p "github.com/fastjack-it/conductor/persistence"
	"github.com/fastjack-it/conductor/utils"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

type TokenResponse struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	RefreshToken string    `json:"refresh_token"`
	Expires      time.Time `json:"expires_in"`
}

type TokenRequest struct {
	RedirectUri       string   `json:"redirect_uri"`
	AuthorizationCode string   `json:"authorization_code"`
	Scope             []string `json:"scope"`
}

type AuthenticationRequest struct {
	Email             string `json:"email"`
	Password          string `json:"password"`
	AuthorizationCode string `json:"authorization_code"`
}

type AuthenticationState struct {
	user         models.UserAccount
	client       models.Client
	tokenRequest TokenRequest
	timestamp    time.Time
}

type EntityType string

const (
	user     EntityType = "user"
	client   EntityType = "client"
	redirect EntityType = "redirect"
	scope    EntityType = "scope"
)

type authHandler struct {
	pendingAuthorizations map[string]*AuthenticationState
}

var Auth = &authHandler{
	pendingAuthorizations: make(map[string]*AuthenticationState),
}

func (ah *authHandler) startWorker() {
	ticker := time.NewTicker(60 * time.Second)
	go func() {
		for {
			select {
			case <-ticker.C:
				ah.cleanUpAuthState()
			}
		}
	}()
}

func (as *AuthenticationState) getUserId() string {
	return as.user.Uuid
}

func (as *AuthenticationState) SetPassword(entityType EntityType, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	switch entityType {
	case user:
		as.user.Password = string(hash)
	case client:
		as.client.Secret = string(hash)
	default:
		return fmt.Errorf("invalid entity type: %s", entityType)
	}
	return nil
}

func (as *AuthenticationState) IsPasswordValid(entityType EntityType, password string) bool {
	var hashedPassword string
	switch EntityType(entityType) {
	case user:
		hashedPassword = as.user.Password
	case client:
		hashedPassword = as.client.Secret
	default:
		return false
	}
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

func (as *AuthenticationState) Set(entityType EntityType, entity interface{}) *AuthenticationState {
	switch EntityType(entityType) {
	case user:
		if user, ok := entity.(models.UserAccount); ok {
			as.user = user
		}
	case client:
		if client, ok := entity.(models.Client); ok {
			as.client = client
		}
	case redirect:
		if redirect, ok := entity.(string); ok {
			as.client.RedirectUri = redirect
		}
	case scope:
		if scope, ok := entity.([]string); ok {
			as.tokenRequest.Scope = scope
		}
	}
	return as
}

func newAuthenticationState() *AuthenticationState {
	return &AuthenticationState{
		user:         models.UserAccount{},
		client:       models.Client{},
		tokenRequest: TokenRequest{},
		timestamp:    time.Now(),
	}
}

func unauthorized(c *gin.Context) {
	c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
}

func (ah *authHandler) cleanUpAuthState() {
	for key, authState := range ah.pendingAuthorizations {
		if time.Since(authState.timestamp) > time.Duration(config.AuthTimeOut)*time.Second {
			delete(ah.pendingAuthorizations, key)
		}
	}
}

func (ah *authHandler) RequestAccessToken(c *gin.Context) {
	var tokenRequestData TokenRequest
	if err := c.ShouldBindJSON(&tokenRequestData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
		return
	}

	clientId, clientSecret, ok := c.Request.BasicAuth()
	if !ok {
		unauthorized(c)
		return
	}

	authState := newAuthenticationState().
		Set(client, models.Client{Id: clientId}).
		Set(user, models.UserAccount{}).
		Set(redirect, tokenRequestData.RedirectUri).
		Set(scope, tokenRequestData.Scope)

	dbClient, err := p.Db.GetClientById(clientId)
	if err != nil {
		unauthorized(c)
		return
	}

	if err = authState.SetPassword(client, clientSecret); err != nil || !authState.IsPasswordValid(client, dbClient.Secret) {
		unauthorized(c)
		return
	}

	ah.pendingAuthorizations[tokenRequestData.AuthorizationCode] = authState
	c.Redirect(http.StatusFound, `${config.EndpointUrl}/oauth/login?authorization_code=${tokenRequestData.AuthorizationCode}`)
}

func (ah *authHandler) LoginPage(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", gin.H{})
}

func (ah *authHandler) IssueToken(c *gin.Context) {
	accessToken, err := utils.GenerateToken(authState.getUserId(), "access", 3600)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate access token"})
		return
	}

	refreshToken, err := utils.GenerateToken(authState.getUserId(), "refresh", 7200)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate refresh token"})
		return
	}

	response := TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "bearer",
		RefreshToken: refreshToken,
		Expires:      time.Now().Add(time.Duration(config.ExpirySeconds) * time.Second),
	}

	if !exists {
		unauthorized(c)
		return
	}

	if !authState.Validate(clientEntity.Id) {
		unauthorized(c)
		return
	}

	delete(a.pendingAuthorizations, tokenRequestEntity.AuthorizationCode)
	c.JSON(http.StatusOK, response)
}

func (ah *authHandler) ValidateToken(c *gin.Context) {
	tokenString := c.Request.Header.Get("Authorization")
	if tokenString == "" {
		unauthorized(c)
		return
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(config.SecretKey), nil
	})

	if err != nil || !token.Valid {
		unauthorized(c)
		return
	}

	c.Status(http.StatusOK)
}

func (ah *authHandler) Authentication(c *gin.Context) {

	userAccount, err := p.Db.GetUserByEmail(email)
	if err != nil {
		unauthorized(c)
		return
	}

	authState := AuthenticationState{
		user: *userAccount,
	}

	secretCode := utils.GenerateSecretCode()
	Auth.pendingAuthorizations[secretCode] = authState

	c.JSON(http.StatusOK, gin.H{"secret_code": secretCode})
}
