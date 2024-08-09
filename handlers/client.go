package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/head-crash/conductor/models"
	"github.com/head-crash/conductor/utils"
	"golang.org/x/crypto/bcrypt"
)

type client struct {
	*models.Client
}

type ClientHandler struct {
	db models.Database
}

func NewClientHandler(db models.Database) *ClientHandler {
	return &ClientHandler{db}
}

func NewClient() *client {
	return &client{
		&models.Client{},
	}
}

func (c *client) SetId(id string) *client {
	c.Id = id
	return c
}

func (c *client) SetSecret(secret string) *client {
	c.Secret = secret
	return c
}

func (c *client) SetRedirectUrl(redirectUrl string) *client {
	c.RedirectUrl = redirectUrl
	return c
}

func (c *client) ApiClientResponse() *models.CreateClientResponseBody {
	return &models.CreateClientResponseBody{
		ClientId:    c.Id,
		RedirectUrl: c.RedirectUrl,
	}
}

func (ch *ClientHandler) Create(c *gin.Context) {
	var createClientRequest models.CreateClientRequestBody
	if err := c.ShouldBindJSON(&createClientRequest); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	if utils.Include([]string{createClientRequest.Secret, createClientRequest.RedirectUrl}, "") {
		c.JSON(400, gin.H{"error": "secret and redirect_url are required"})
		return
	}

	if encryptedSecret, err := bcrypt.GenerateFromPassword([]byte(createClientRequest.Secret), bcrypt.DefaultCost); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Secret encryption failed"})
		return
	} else {
		newClient := NewClient().
			SetId(uuid.New().String()).
			SetSecret(string(encryptedSecret)).
			SetRedirectUrl(createClientRequest.RedirectUrl)

		if err := ch.db.CreateClient(newClient.Client); err != nil {
			c.JSON(http.StatusConflict, gin.H{"error": "client creation failed"})
			return
		}

		c.JSON(http.StatusCreated, newClient.ApiClientResponse())
	}
}

func (ch *ClientHandler) GetClients(c *gin.Context) {
	limit := utils.StrToInt(c.DefaultQuery("limit", "100"))
	offset := utils.StrToInt(c.DefaultQuery("offset", "0"))
	clients, err := ch.db.GetClients(offset, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"clients": clients})
}

func (ch *ClientHandler) Delete(c *gin.Context) {
	clientId := c.Param("clientId")
	if err := ch.db.DeleteClient(clientId); err != nil {
		log.Error("Failed to delete client: %s", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Client deleted"})
}
