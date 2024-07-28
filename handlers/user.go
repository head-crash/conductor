package handlers

import (
	"net/http"

	"github.com/fastjack-it/conductor/models"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
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

func (u *user) Set(entity EntityType, value string) *user {
	switch entity {
	case EMAIL:
		u.Email = value
	case PASSWORD:
		u.Password = value
	case ROLE:
		if models.Role(value).IsValid() {
			u.Role = models.Role(value)
		}
	case ID:
		u.Uuid = value
	}
	return u
}

func (uh *UserHandler) Create(c *gin.Context) {
	var createUserRequest models.CreateUserRequestBody
	if err := c.ShouldBindJSON(&createUserRequest); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	newUser := NewUser().
		Set(EMAIL, createUserRequest.Email).
		Set(PASSWORD, createUserRequest.Password).
		Set(ROLE, string(models.USER)).
		Set(ID, uuid.New().String())

	if err := uh.db.CreateUser(newUser.UserAccount); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "A user with that email already exists"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User created"})
}
