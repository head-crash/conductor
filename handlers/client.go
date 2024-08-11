package handlers

import (
	"encoding/base64"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/head-crash/conductor/models"
	"github.com/head-crash/conductor/utils"
	"golang.org/x/crypto/bcrypt"
)

// client represents an OAuth client with an embedded Client model.
type client struct {
	*models.Client
}

// ClientHandler handles client-related operations and interactions with the database.
type ClientHandler struct {
	db models.Database
}

// NewClientHandler creates a new ClientHandler with the provided database.
func NewClientHandler(db models.Database) *ClientHandler {
	return &ClientHandler{db}
}

// NewClient creates a new client instance.
func NewClient() *client {
	return &client{
		&models.Client{},
	}
}

// SetId sets the ID of the client.
func (c *client) SetId(id string) *client {
	c.Id = id
	return c
}

// SetSecret sets the secret of the client.
func (c *client) SetSecret(secret string) *client {
	c.Secret = secret
	return c
}

// SetRedirectUrl sets the redirect URL of the client.
func (c *client) SetRedirectUrl(redirectUrl string) *client {
	c.RedirectUrl = redirectUrl
	return c
}

// ApiClientResponse returns the API response body for the client creation.
func (c *client) ApiClientResponse() *models.CreateClientResponseBody {
	return &models.CreateClientResponseBody{
		ClientId:    c.Id,
		RedirectUrl: c.RedirectUrl,
	}
}

// Create handles the creation of a new client from JSON data and responds with the appropriate HTTP status.
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
			SetId(base64.URLEncoding.EncodeToString([]byte(uuid.New().String()))).
			SetSecret(string(encryptedSecret)).
			SetRedirectUrl(createClientRequest.RedirectUrl)

		if err := ch.db.CreateClient(newClient.Client); err != nil {
			c.JSON(http.StatusConflict, gin.H{"error": "client creation failed"})
			return
		}

		c.JSON(http.StatusCreated, newClient.ApiClientResponse())
	}
}

// GetClients retrieves a list of clients with pagination and responds with the appropriate HTTP status.
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

// Delete removes a client by their ID and responds with the appropriate HTTP status.
func (ch *ClientHandler) Delete(c *gin.Context) {
	clientId := c.Param("clientId")
	if err := ch.db.DeleteClient(clientId); err != nil {
		log.Error("Failed to delete client: %s", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Client deleted"})
}
