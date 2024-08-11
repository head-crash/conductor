package handlers

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/head-crash/conductor/config"
	"github.com/head-crash/conductor/models"
	"github.com/head-crash/conductor/utils"
	"golang.org/x/crypto/bcrypt"
)

// User represents a user with an embedded UserAccount.
type User struct {
	*models.UserAccount
}

// UserHandler handles user-related operations and interactions with the database.
type UserHandler struct {
	db                    models.Database
	pendingPasswordResets map[string]*User
}

// deletePendingPasswordResets deletes all pending password reset tokens.
func (uh *UserHandler) deletePendingPasswordResets() {
	for token := range uh.pendingPasswordResets {
		delete(uh.pendingPasswordResets, token)
	}
}

// StartCleanUpTicker starts a ticker that periodically cleans up pending password resets.
func (uh *UserHandler) StartCleanUpTicker() *UserHandler {
	ticker := time.NewTicker(24 * time.Hour)
	go func() {
		for range ticker.C {
			uh.deletePendingPasswordResets()
		}
	}()
	return uh
}

// NewUserHandler creates a new UserHandler with the provided database and starts the cleanup ticker.
func NewUserHandler(db models.Database) *UserHandler {
	return (&UserHandler{db, make(map[string]*User)}).StartCleanUpTicker()
}

// NewUser creates a new User instance.
func NewUser() *User {
	return &User{
		&models.UserAccount{},
	}
}

// SetEmail sets the email of the user.
func (u *User) SetEmail(email string) *User {
	u.Email = email
	return u
}

// SetPassword sets the password of the user.
func (u *User) SetPassword(password string) *User {
	u.Password = password
	return u
}

// SetRole sets the role of the user if it is valid.
func (u *User) SetRole(role string) *User {
	if models.Role(role).IsValid() {
		u.Role = models.Role(role)
	}
	return u
}

// SetId sets the UUID of the user.
func (u *User) SetId(id string) *User {
	u.Uuid = id
	return u
}

// setEncryptedPassword encrypts the password and sets it for the user.
func (u *User) setEncryptedPassword(password string) *User {
	encryptedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Error("Error encrypting password: %s", err)
		panic(err)
	}
	u.Password = string(encryptedPassword)
	return u
}

// NewUserFromRegistration creates a new user from registration details.
func (uh *UserHandler) NewUserFromRegistration(email, password string) *User {
	newUser := NewUser().
		SetEmail(email).
		setEncryptedPassword(password).
		SetRole(string(models.USER)).
		SetId(uuid.New().String())

	return newUser
}

// CreateUserFromForm creates a new user from form data and handles the HTTP response.
func (uh *UserHandler) CreateUserFromForm(c *gin.Context) {
	email := c.PostForm("email")
	password := c.PostForm("password")
	if email == "" || password == "" {
		c.Redirect(http.StatusFound, "/oauth/login?error="+url.PathEscape("Email and password are required"))
		return
	}
	newUser := uh.NewUserFromRegistration(email, password)
	if err := uh.db.CreateUser(newUser.UserAccount); err != nil {
		c.Redirect(http.StatusFound, "/oauth/login?register=true&error="+url.PathEscape("a user with that email already exists"))
		return
	}
	c.Redirect(http.StatusFound, "/oauth/login?info="+url.PathEscape("Account successfully created"))
}

// Create creates a new user from JSON data and handles the HTTP response.
func (uh *UserHandler) Create(c *gin.Context) {
	var createUserRequest models.CreateUserRequestBody
	if err := c.ShouldBindJSON(&createUserRequest); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	newUser := NewUser().
		SetEmail(createUserRequest.Email).
		setEncryptedPassword(createUserRequest.Password).
		SetRole(string(models.USER)).
		SetId(uuid.New().String())

	if err := uh.db.CreateUser(newUser.UserAccount); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "A user with that email already exists"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User created"})
}

// IsAdmin checks if the user has an admin role.
func (u *User) IsAdmin() bool {
	return u.Role == models.ADMIN
}

// GetUserFromContext retrieves the user from the Gin context.
func GetUserFromContext(c *gin.Context) *User {
	user, exists := c.Get("user")
	if !exists {
		return nil
	}
	return user.(*User)
}

// IsAdmin checks if the user in the context is an admin and handles the HTTP response.
func (uh *UserHandler) IsAdmin(c *gin.Context) {
	user := GetUserFromContext(c)
	if user == nil {
		unauthorized(c)
		c.Abort()
		return
	}
	if !user.IsAdmin() {
		unauthorized(c)
		c.Abort()
		return
	}
	c.Next()
}

// SetNewPassword sets a new password for the user and handles the HTTP response.
func (uh *UserHandler) SetNewPassword(c *gin.Context) {
	userId := c.Param("userId")
	newPasswordRequestbody := models.SetUserPasswordRequestBody{}
	if err := c.ShouldBindJSON(&newPasswordRequestbody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		c.Abort()
		return
	}
	userAccount, err := uh.db.GetUserById(userId)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		c.Abort()
		return
	}
	user := NewUser().
		SetId(userAccount.Uuid).
		SetEmail(userAccount.Email).
		SetRole(string(userAccount.Role)).
		setEncryptedPassword(newPasswordRequestbody.Password)

	if err := uh.db.UpdateUser(user.UserAccount); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("DB user update failed: %s", err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Password updated"})
}

// GetUsers retrieves a list of users and handles the HTTP response.
func (uh *UserHandler) GetUsers(c *gin.Context) {
	limit := utils.StrToInt(c.DefaultQuery("limit", "100"))
	offset := utils.StrToInt(c.DefaultQuery("offset", "0"))
	users, err := uh.db.GetUsers(offset, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"users": users})
}

// Delete removes a user by their ID and handles the HTTP response.
func (uh *UserHandler) Delete(c *gin.Context) {
	userId := c.Param("userId")
	if err := uh.db.DeleteUser(userId); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "User deleted"})
}

// ResetPasswordForm handles the password reset form submission and sends a reset email.
func (uh *UserHandler) ResetPasswordForm(c *gin.Context) {
	email := c.PostForm("email")
	if email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Email is required"})
		return
	}

	user, err := uh.db.GetUserByEmail(email)
	if err != nil || user == nil {
		c.Redirect(http.StatusOK, "/oauth/login?error="+url.PathEscape("Password reset email sent, if user exists"))
		return
	}

	resetCode, err := bcrypt.GenerateFromPassword([]byte(uuid.New().String()), bcrypt.DefaultCost)
	if err != nil {
		log.Error("Error encrypting resetToken: %s for user %s", err, user.Email)
		c.Redirect(http.StatusFound, "/oauth/login?error="+url.PathEscape("Error resetting password, try again later!"))
		return
	}
	resetToken := base64.URLEncoding.EncodeToString(resetCode)
	uh.pendingPasswordResets[resetToken] = &User{user}
	resetLink := fmt.Sprintf("%s/users/reset-password?resetToken=%s", config.EndpointUrl, url.PathEscape(resetToken))

	mailBody := fmt.Sprintf("Click the link to reset your password on %s: %s", config.Title, resetLink)
	mailSubject := fmt.Sprintf("%s password reset", config.Title)

	if err := utils.SendMail(config.SMTPConfig, user.Email, mailSubject, mailBody); err != nil {
		c.Redirect(http.StatusFound, "/oauth/login?error="+url.PathEscape("Error sending mail, try again later!"))
	}
	log.Debug("current pendingPasswordReset state: %v+", uh.pendingPasswordResets)
	c.Redirect(http.StatusFound, "/oauth/login?info="+url.PathEscape("Password reset email sent"))
}

// invalidResetToken handles invalid reset token responses.
func invalidResetToken(c *gin.Context) {
	c.Redirect(http.StatusFound, "/oauth/login?error="+url.PathEscape("Invalid reset token"))
	c.Abort()
}

// ResetPasswortPage displays the password reset page if the reset token is valid.
func (uh *UserHandler) ResetPasswortPage(c *gin.Context) {
	resetToken := c.Query("resetToken")
	log.Debug("Requested resetToken: %s", resetToken)
	_, exists := uh.pendingPasswordResets[resetToken]
	if !exists {
		log.Debug("current pendingPasswordResets state: %v+", uh.pendingPasswordResets)
		invalidResetToken(c)
		return
	}
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(config.MainTemplate))
}

// ResetPassword resets the user's password if the reset token is valid and handles the HTTP response.
func (uh *UserHandler) ResetPassword(c *gin.Context) {
	resetToken := c.PostForm("resetToken")
	newPassword := c.PostForm("new-password")
	user, exists := uh.pendingPasswordResets[resetToken]
	if !exists {
		invalidResetToken(c)
		return
	}

	user.setEncryptedPassword(newPassword)

	if err := uh.db.UpdateUser(user.UserAccount); err != nil {
		c.Redirect(http.StatusFound, "/oauth/login?info="+url.PathEscape("Error resetting password"))
	}

	delete(uh.pendingPasswordResets, resetToken)
	c.Redirect(http.StatusFound, "/oauth/login?info="+url.PathEscape("Password successfully reseted"))
}
