package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/head-crash/conductor/models"
	"github.com/head-crash/conductor/utils"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	*models.UserAccount
}

type UserHandler struct {
	db models.Database
}

func NewUserHandler(db models.Database) *UserHandler {
	return &UserHandler{db}
}

func NewUser() *User {
	return &User{
		&models.UserAccount{},
	}
}

func (u *User) SetEmail(email string) *User {
	u.Email = email
	return u
}

func (u *User) SetPassword(password string) *User {
	u.Password = password
	return u
}

func (u *User) SetRole(role string) *User {
	if models.Role(role).IsValid() {
		u.Role = models.Role(role)
	}
	return u
}

func (u *User) SetId(id string) *User {
	u.Uuid = id
	return u
}

func (u *User) setEncryptedPassword(password string) *User {
	encryptedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Error("Error encrypting password: %s", err)
		panic(err)
	}
	u.Password = string(encryptedPassword)
	return u
}

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

func (u *User) IsAdmin() bool {
	return u.Role == models.ADMIN
}

func GetUserFromContext(c *gin.Context) *User {
	user, exists := c.Get("user")
	if !exists {
		return nil
	}
	return user.(*User)
}

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

func (uh *UserHandler) Delete(c *gin.Context) {
	userId := c.Param("userId")
	if err := uh.db.DeleteUser(userId); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "User deleted"})
}
