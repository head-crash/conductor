package handlers

import (
	"encoding/base64"
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

func GenerateToken(userId string, tokenType TokenType, expiresIn int64) (string, error) {
	claims := jwt.MapClaims{
		"exp": time.Now().Add(time.Duration(expiresIn) * time.Second).Unix(),
		"sub": userId,
		"iss": config.EndpointUrl,
		"typ": tokenType,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(config.SecretKey))
}

func GetUserIdFromAccessToken(tokenString string) (string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(config.SecretKey), nil
	})
	if err != nil {
		return "", err
	}
	if !token.Valid {
		return "", fmt.Errorf("invalid token")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("failed to parse claims")
	}
	if claims["typ"] != string(ACCESS_TOKEN) {
		log.Debug("Token is not of type refresh")
		return "", fmt.Errorf("token is not of type refresh")
	}

	return claims["sub"].(string), nil
}

func GetUserIdFromRefreshToken(tokenString string) (string, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(config.SecretKey), nil
	})
	if err != nil {
		log.Debug("Failed to parse token: %s", err)
		return "", err
	}
	if !token.Valid {
		log.Debug("Invalid token")
		return "", fmt.Errorf("invalid token")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		log.Debug("Failed to parse claims")
		return "", fmt.Errorf("failed to parse claims")
	}
	if claims["typ"] != string(REFRESH_TOKEN) {
		log.Debug("Token is not of type refresh")
		return "", fmt.Errorf("token is not of type refresh")
	}

	return claims["sub"].(string), nil
}

func GetTokenResponse(userId string) (*models.TokenResponseBody, error) {
	accessToken, err := GenerateToken(userId, ACCESS_TOKEN, 3600)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := GenerateToken(userId, REFRESH_TOKEN, 7200)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return &models.TokenResponseBody{
		AccessToken: accessToken,
		TokenResponse: &models.TokenResponse{
			TokenType: "bearer",
			Expires:   time.Now().Add(time.Duration(config.ExpirySeconds) * time.Second),
		},
		RefreshToken: refreshToken,
	}, nil
}

func newAuthenticationCode() string {
	authCode, err := bcrypt.GenerateFromPassword([]byte(uuid.New().String()), bcrypt.DefaultCost)
	if err != nil {
		log.Warn("Error encrypting authCode: %s -> fallback to decrypted authCode!", err)
		return base64.URLEncoding.EncodeToString([]byte(uuid.New().String()))
	}
	return base64.URLEncoding.EncodeToString(authCode)
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

func (ah *AuthHandler) Init() *AuthHandler {
	// create admin user if no users exist
	users, err := ah.db.GetUsers(0, 1)
	if err != nil {
		log.Error("init of AuthHandler faild: Failed to get users: %s", err)
		return ah
	}
	if len(users) == 0 {
		randPassword := base64.URLEncoding.EncodeToString(([]byte(uuid.New().String())))
		adminUser := NewUser().
			SetEmail(config.AdminUserName).
			setEncryptedPassword(randPassword).
			SetRole(string(models.ADMIN)).
			SetId(uuid.New().String())

		if err := ah.db.CreateUser(adminUser.UserAccount); err != nil {
			log.Error("init of AuthHandler faild: Failed to create admin user: %s", err)
			return ah
		}

		log.Info("Empty user db. Created admin user %s with password %s", config.AdminUserName, randPassword)
		return ah
	}
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
		authorizationCode: newAuthenticationCode(),
	}
}

func unauthorized(c *gin.Context) {
	c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
	c.Abort()
}

func (ah *AuthHandler) ValidateAuthorization(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		unauthorized(c)
		return
	}

	tokenString := strings.Replace(authHeader, "Bearer ", "", 1)
	userId, err := GetUserIdFromAccessToken(tokenString)
	if err != nil {
		unauthorized(c)
		return
	}

	dbUser, err := ah.db.GetUserById(userId)
	if err != nil || dbUser == nil {
		unauthorized(c)
		return
	}

	user := NewUser().
		SetEmail(dbUser.Email).
		SetPassword(dbUser.Password).
		SetRole(string(dbUser.Role)).
		SetId(dbUser.Uuid)

	c.Set("user", user)
	c.Next()
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
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(config.MainTemplate))
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

func (ah *AuthHandler) AuthenticateOauth(c *gin.Context) {
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

func (ah *AuthHandler) Authenticate(c *gin.Context) {
	email, pass, ok := c.Request.BasicAuth()
	if !ok || email == "" || pass == "" {
		unauthorized(c)
		return
	}

	dbUser, err := ah.db.GetUserByEmail(email)
	if err != nil || dbUser == nil {
		log.Debug("Invalid email address (local login): %s", email)
		unauthorized(c)
		return
	}

	adminUser := NewUser().
		SetEmail(dbUser.Email).
		SetPassword(dbUser.Password).
		SetRole(string(dbUser.Role)).
		SetId(dbUser.Uuid)

	authState := newAuthenticationState().
		SetUser(*adminUser.UserAccount).
		SetScope([]string{"admin"})

	if !authState.IsUserPasswordValid(pass) {
		log.Debug("Invalid password for user (logal login): %s", email)
		unauthorized(c)
		return
	}

	response, err := GetTokenResponse(authState.getUserId())
	if err != nil {
		log.Error("Failed to generate token (local login): %s", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, response)
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

		response, err := GetTokenResponse(authState.getUserId())
		if err != nil {
			log.Error("Failed to generate token: %s", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
			return
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

	if userId, err := GetUserIdFromAccessToken(tokenString); err != nil {
		unauthorized(c)
		return
	} else {
		c.JSON(http.StatusOK, gin.H{"user_id": userId})
	}
}

func (ah *AuthHandler) RenewToken(c *gin.Context) {
	tokenString := c.Request.Header.Get("Authorization")
	if tokenString == "" {
		unauthorized(c)
		return
	}

	// Remove the "Bearer " prefix from the token string
	tokenString = strings.Replace(tokenString, "Bearer ", "", 1)

	userId, err := GetUserIdFromRefreshToken(tokenString)
	if err != nil {
		unauthorized(c)
		return
	}

	response, err := GetTokenResponse(userId)
	if err != nil {
		log.Error("Failed to generate token: %s", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	renewToken := &models.RenewTokenRequestBody{
		AccessToken: response.AccessToken,
		TokenResponse: &models.TokenResponse{
			TokenType: response.TokenType,
			Expires:   response.Expires,
		},
	}

	c.JSON(http.StatusOK, renewToken)
}
