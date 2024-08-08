package handlers

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/head-crash/conductor/config"
	"github.com/head-crash/conductor/models"
	"github.com/head-crash/logger"
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

var log = logger.Default

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

func (as *AuthenticationState) IsUserPasswordValid(password string) bool {
	hashedPassword := as.user.Password
	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)); err != nil {
		return false
	}
	return true
}

func (as *AuthenticationState) IsClientSecretValid(secret string) bool {
	hashedSecret := as.client.Secret
	if err := bcrypt.CompareHashAndPassword([]byte(hashedSecret), []byte(secret)); err != nil {
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

func (as *AuthenticationState) SetUser(user models.UserAccount) *AuthenticationState {
	as.user = user
	return as
}

func (as *AuthenticationState) SetClient(client models.Client) *AuthenticationState {
	as.client = client
	return as
}

func (as *AuthenticationState) SetScope(scope []string) *AuthenticationState {
	as.scope = scope
	return as
}

func (as *AuthenticationState) SetState(state string) *AuthenticationState {
	as.state = state
	return as
}

func (as *AuthenticationState) SetPassword(password string) *AuthenticationState {
	if pw, err := as.generateEncryptedSecret(password); err != nil {
		log.Error("Failed to hash password: %s", err)
	} else {
		as.user.Password = pw
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
	dbAccount, err := ah.db.GetUserByEmail(c.PostForm("email"))
	if err != nil || dbAccount == nil {
		log.Debug("Invalid email address: %s", c.PostForm("email"))
		ah.LoginPageError(c, "Login failed! Invalid credentials.")
		return
	}
	authState := newAuthenticationState().
		SetUser(*dbAccount).
		SetScope(strings.Split(c.PostForm("scope"), "-")).
		SetState(c.PostForm("state"))

	if !authState.IsUserPasswordValid(c.PostForm("password")) {
		log.Debug("Invalid password for user: %s", c.PostForm("email"))
		ah.LoginPageError(c, "Login failed! Invalid credentials.")
		return
	}

	dbClient, err := ah.db.GetClientById(c.PostForm("client_id"))
	if err != nil || dbClient == nil {
		log.Debug("Failed to get client by id: %s", err)
		ah.LoginPageError(c, "Login failed! Invalid credentials.")
		return
	}
	authState.SetClient(*dbClient)

	ah.addPendingAuthorization(authState)
	c.Redirect(http.StatusFound, authState.getClientRedirectUrl())
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

		if !authState.IsClientSecretValid(clientSecret) || clientId != authState.client.Id {
			unauthorized(c)
			return
		}

		accessToken, err := GenerateToken(authState.getUserId(), "access", 3600)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate access token"})
			return
		}

		refreshToken, err := GenerateToken(authState.getUserId(), "refresh", 7200)
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

	if userId, err := ValidateToken(tokenString); err != nil {
		unauthorized(c)
		return
	} else {
		c.JSON(http.StatusOK, gin.H{"user_id": userId})
	}
}
