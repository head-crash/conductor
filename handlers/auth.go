package handlers

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fastjack-it/conductor/config"
	"github.com/fastjack-it/conductor/models"
	"github.com/fastjack-it/conductor/utils"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type AuthenticationState struct {
	user              models.UserAccount
	client            models.Client
	state             string
	scope             []string
	timestamp         time.Time
	authorizationCode string
}

type AuthHandler struct {
	pendingAuthorizations map[string]*AuthenticationState
	db                    models.Database
}

func NewAuthHandler(db models.Database) *AuthHandler {
	return &AuthHandler{
		pendingAuthorizations: make(map[string]*AuthenticationState),
		db:                    db,
	}
}

func (ah *AuthHandler) StartCleanUp() *AuthHandler {
	ticker := time.NewTicker(60 * time.Second)
	go func() {
		for range ticker.C {
			ah.cleanUpAuthState()
		}
	}()
	return ah
}

func (as *AuthenticationState) getUserId() string {
	return as.user.Uuid
}

func (as *AuthenticationState) IsPasswordValid(entityType EntityType, password string) bool {
	var hashedPassword string
	log.Default().Printf("Checking password %s for %s", password, entityType)
	switch EntityType(entityType) {
	case USER:
		hashedPassword = as.user.Password
	case CLIENT:
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
	case USER:
		if user, ok := entity.(models.UserAccount); ok {
			as.user = user
		}
	case CLIENT:
		if client, ok := entity.(models.Client); ok {
			as.client = client
		}
	case SCOPE:
		if scope, ok := entity.([]string); ok {
			as.scope = scope
		}
	case STATE:
		if state, ok := entity.(string); ok {
			as.state = state
		}
	case PASSWORD:
		if pw, ok := entity.(string); ok {
			if pw, err := as.generateEncryptedSecret(pw); err != nil {
				log.Printf("[error] Failed to hash password: %s", err)
			} else {
				as.user.Password = pw
			}
		}
	case SECRET:
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

func (ah *AuthHandler) addPendingAuthorization(authState *AuthenticationState) {
	if _, exists := ah.pendingAuthorizations[authState.authorizationCode]; exists {
		ah.deletePendingAuthorization(authState.state)
	}
	ah.pendingAuthorizations[authState.authorizationCode] = authState
}

func (ah *AuthHandler) getAuthenticationState(authorizationCode string) (*AuthenticationState, error) {
	if authState, exists := ah.pendingAuthorizations[authorizationCode]; exists {
		return authState, nil
	}
	return nil, fmt.Errorf("authorization code is invalid")
}

func (ah *AuthHandler) deletePendingAuthorization(authorizationCode string) {
	delete(ah.pendingAuthorizations, authorizationCode)
}

func (ah *AuthHandler) cleanUpAuthState() {
	for key, authState := range ah.pendingAuthorizations {
		if time.Since(authState.timestamp) > time.Duration(config.AuthTimeOut)*time.Second {
			ah.deletePendingAuthorization(key)
		}
	}
}

func (ah *AuthHandler) LoginPage(c *gin.Context) {
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(config.LoginHtml))
}

func (ah *AuthHandler) LoginPageError(c *gin.Context, m ErrorMessage) {
	var errorMessage string
	if m == "" {
		errorMessage = string(ERR_CREDENTIALS)
	} else {
		errorMessage = string(m)
	}
	c.Redirect(http.StatusFound,
		"/oauth/login?error="+
			url.PathEscape(errorMessage)+
			"&state="+
			url.PathEscape(c.PostForm("state"))+
			"&client_id="+
			url.PathEscape(c.PostForm("client_id"))+
			"&scope="+
			url.PathEscape((c.PostForm("scope"))))
}

func (ah *AuthHandler) Authenticate(c *gin.Context) {
	authState := newAuthenticationState().
		Set(USER, models.UserAccount{Email: c.PostForm("email")}).
		Set(CLIENT, models.Client{Id: c.PostForm("client_id")}).
		Set(SCOPE, strings.Split(c.PostForm("scope"), "")).
		Set(STATE, c.PostForm("state")).
		Set(PASSWORD, c.PostForm("password"))

	if userAccount, err := ah.db.GetUserByEmail(c.PostForm("email")); err != nil || userAccount == nil {
		ah.LoginPageError(c, ERR_CREDENTIALS)
		return
	} else {
		if !authState.IsPasswordValid(USER, userAccount.Password) {
			ah.LoginPageError(c, ERR_CREDENTIALS)
			return
		}
		authState.Set(USER, *userAccount)
		dbClient, err := ah.db.GetClientById(c.PostForm("client_id"))
		if err != nil || dbClient == nil {
			ah.LoginPageError(c, ERR_CLIENT_ID)
			return
		}
		authState.Set(CLIENT, *dbClient)

		ah.addPendingAuthorization(authState)
		c.Redirect(http.StatusFound, authState.getClientRedirectUrl())
	}
}

func (ah *AuthHandler) IssueToken(c *gin.Context) {
	if clientId, clientSecret, ok := c.Request.BasicAuth(); !ok {
		unauthorized(c)
		return
	} else {
		authorizationCode := c.Query("authorization_code")
		authState, err := ah.getAuthenticationState(authorizationCode)
		if err != nil {
			unauthorized(c)
			return
		}

		if !authState.IsPasswordValid(CLIENT, clientSecret) || clientId != authState.client.Id {
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

		response := models.TokenResponseBody{
			AccessToken:  accessToken,
			TokenType:    "bearer",
			RefreshToken: refreshToken,
			Expires:      time.Now().Add(time.Duration(config.ExpirySeconds) * time.Second),
		}

		ah.deletePendingAuthorization(authorizationCode)
		c.JSON(http.StatusOK, response)
	}
}

func (ah *AuthHandler) ValidateToken(c *gin.Context) {
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
