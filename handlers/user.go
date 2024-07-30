package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/head-crash/conductor/models"
	"golang.org/x/crypto/bcrypt"
)

type user struct {
	*models.UserAccount
}

type UserHandler struct {
	db models.Database
}

func NewUserHandler(db models.Database) *UserHandler {
	return &UserHandler{db}
}

func NewUser() *user {
	return &user{
		&models.UserAccount{},
	}
}

func (u *user) SetEmail(email string) *user {
	u.Email = email
	return u
}

func (u *user) SetPassword(password string) *user {
	u.Password = password
	return u
}

func (u *user) SetRole(role string) *user {
	if models.Role(role).IsValid() {
		u.Role = models.Role(role)
	}
	return u
}

func (u *user) SetId(id string) *user {
	u.Uuid = id
	return u
}

func (uh *UserHandler) Create(c *gin.Context) {
	var createUserRequest models.CreateUserRequestBody
	if err := c.ShouldBindJSON(&createUserRequest); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if encryptedPassword, err := bcrypt.GenerateFromPassword([]byte(createUserRequest.Password), bcrypt.DefaultCost); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Pasword encryption failed"})
		return
	} else {
		newUser := NewUser().
			SetEmail(createUserRequest.Email).
			SetPassword(string(encryptedPassword)).
			SetRole(string(models.USER)).
			SetId(uuid.New().String())

		if err := uh.db.CreateUser(newUser.UserAccount); err != nil {
			c.JSON(http.StatusConflict, gin.H{"error": "A user with that email already exists"})
			return
		}

		c.JSON(http.StatusCreated, gin.H{"message": "User created"})
	}
}
