package main

import (
	"log"

	"github.com/fastjack-it/conductor/config"
	"github.com/fastjack-it/conductor/handlers"
	"github.com/gin-gonic/gin"
)

func main() {
	config.LoadConfig()

	r := gin.Default()

	r.POST("/oauth/token", handlers.TokenHandler)
	r.GET("/oauth/authorize", handlers.AuthorizeHandler)
	r.POST("/oauth/authorize", handlers.AuthorizeHandler)

	log.Println("OAuth server is running on port 8080")
	log.Fatal(r.Run(":8080"))
}
