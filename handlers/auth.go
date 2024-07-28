package handlers

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/fastjack-it/conductor/config"
	"github.com/fastjack-it/conductor/models"
	p "github.com/fastjack-it/conductor/persistence"
	"github.com/fastjack-it/conductor/utils"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type TokenRequest struct {
	RedirectUrl       string   `json:"redirect_url"`
	AuthorizationCode string   `json:"authorization_code"`
	Scope             []string `json:"scope"`
}

type TokenResponse struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	RefreshToken string    `json:"refresh_token"`
	Expires      time.Time `json:"expires_in"`
}

type AuthenticationState struct {
	user              models.UserAccount
	client            models.Client
	state             string
	scope             []string
	timestamp         time.Time
	authorizationCode string
}

type EntityType string

const (
	user     EntityType = "user"
	client   EntityType = "client"
	scope    EntityType = "scope"
	state    EntityType = "state"
	password EntityType = "password"
	secret   EntityType = "secret"
)

type authHandler struct {
	pendingAuthorizations map[string]*AuthenticationState
}

var Auth = &authHandler{
	pendingAuthorizations: make(map[string]*AuthenticationState),
}

func (ah *authHandler) StartCleanUp() {
	ticker := time.NewTicker(60 * time.Second)
	go func() {
		for range ticker.C {
			ah.cleanUpAuthState()
		}
	}()
}

func (as *AuthenticationState) getUserId() string {
	return as.user.Uuid
}

func (as *AuthenticationState) IsPasswordValid(entityType EntityType, password string) bool {
	var hashedPassword string
	log.Default().Printf("Checking password %s for %s", password, entityType)
	switch EntityType(entityType) {
	case user:
		hashedPassword = as.user.Password
	case client:
		hashedPassword = as.client.Secret
	default:
		return false
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)); err != nil {
		log.Printf("[error] Failed to compare password: %s", err)
		return false
	}
	return true
}

func (as *AuthenticationState) generateEncryptedSecret(decryptedPassword string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(decryptedPassword), bcrypt.DefaultCost)
	if err == nil {
		return string(hash), nil
	}
	return "", err
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
	case scope:
		if scope, ok := entity.([]string); ok {
			as.scope = scope
		}
	case state:
		if state, ok := entity.(string); ok {
			as.state = state
		}
	case password:
		if pw, ok := entity.(string); ok {
			if pw, err := as.generateEncryptedSecret(pw); err != nil {
				log.Printf("[error] Failed to hash password: %s", err)
			} else {
				as.user.Password = pw
			}
		}
	case secret:
		if clientSecret, ok := entity.(string); ok {
			if secret, err := as.generateEncryptedSecret(clientSecret); err != nil {
				log.Printf("[error] Failed to hash password: %s", err)
			} else {
				as.client.Secret = secret
			}
		}
	}
	return as
}

func (as *AuthenticationState) getClientRedirectUrl() string {
	return as.client.RedirectUrl + "?state=" + as.state + "&authorization_code=" + as.authorizationCode
}

func newAuthenticationState() *AuthenticationState {
	return &AuthenticationState{
		user:              models.UserAccount{},
		client:            models.Client{},
		state:             "",
		scope:             []string{},
		timestamp:         time.Now(),
		authorizationCode: uuid.New().String(),
	}
}

func unauthorized(c *gin.Context) {
	c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
}

func (ah *authHandler) cleanUpAuthState() {
	for key, authState := range ah.pendingAuthorizations {
		if time.Since(authState.timestamp) > time.Duration(config.AuthTimeOut)*time.Second {
			ah.deletePendingAuthorization(key)
		}
	}
}

func (ah *authHandler) LoginPage(c *gin.Context) {
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(config.LoginHtml))
}

func (ah *authHandler) LoginPageError(c *gin.Context) {
	c.Redirect(http.StatusFound, config.EndpointUrlFor(
		"/oauth/login?error=invalid_credentials&state=",
		c.PostForm("state"),
		"&client_id=", c.PostForm("client_id"),
		"&scope=", c.PostForm("scope"),
		"&redirect_url=", c.PostForm("redirect_url"),
	))
}

func (ah *authHandler) addPendingAuthorization(authState *AuthenticationState) {
	ah.pendingAuthorizations[authState.authorizationCode] = authState
}

func (ah *authHandler) deletePendingAuthorization(state string) {
	delete(ah.pendingAuthorizations, state)
}

func (ah *authHandler) validateAuthcode(authcode string) (*AuthenticationState, error) {
	authState, exists := ah.pendingAuthorizations[authcode]
	if !exists {
		return nil, fmt.Errorf("invalid authorization code")
	}
	return authState, nil
}

func (ah *authHandler) Authenticate(c *gin.Context) {
	authState := newAuthenticationState().
		Set(user, models.UserAccount{Email: c.PostForm("email")}).
		Set(client, models.Client{Id: c.PostForm("client_id")}).
		Set(scope, strings.Split(c.PostForm("scope"), "")).
		Set(state, c.PostForm("state")).
		Set(password, c.PostForm("password"))

	if userAccount, err := p.Db.GetUserByEmail(c.PostForm("email")); err != nil || userAccount == nil {
		ah.LoginPageError(c)
		return
	} else {
		if !authState.IsPasswordValid(user, userAccount.Password) {
			ah.LoginPageError(c)
			return
		}
		authState.Set(user, *userAccount)
	}

	if dbClient, err := p.Db.GetClientById(c.PostForm("client_id")); err != nil || dbClient == nil {
		ah.LoginPageError(c)
		return
	} else {
		authState.Set(client, *dbClient)
	}

	ah.addPendingAuthorization(authState)
	c.Redirect(http.StatusFound, authState.getClientRedirectUrl())
}

func (ah *authHandler) IssueToken(c *gin.Context) {
	if clientId, clientSecret, ok := c.Request.BasicAuth(); !ok {
		unauthorized(c)
		return
	} else {
		var tokenRequest TokenRequest
		if err := c.ShouldBindJSON(&tokenRequest); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}

		authState, err := ah.validateAuthcode(tokenRequest.AuthorizationCode)
		if err != nil {
			unauthorized(c)
			return
		}

		if !authState.IsPasswordValid(client, clientSecret) || clientId != authState.client.Id {
			unauthorized(c)
			return
		}

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

		ah.deletePendingAuthorization(tokenRequest.AuthorizationCode)
		c.JSON(http.StatusOK, response)
	}
}

func (ah *authHandler) ValidateToken(c *gin.Context) {
	tokenString := c.Request.Header.Get("Authorization")
	if tokenString == "" {
		unauthorized(c)
		return
	}

	// Remove the "Bearer " prefix from the token string
	tokenString = strings.Replace(tokenString, "Bearer ", "", 1)

	if userId, err := utils.ValidateToken(tokenString); err != nil {
		unauthorized(c)
		return
	} else {
		c.JSON(http.StatusOK, gin.H{"user_id": userId})
	}
}
