package main

import (
	"log"

	"github.com/fastjack-it/conductor/config"
	"github.com/fastjack-it/conductor/handlers"
	"github.com/fastjack-it/conductor/router"
)

func main() {
	config.LoadConfig()
	r := router.Init()
	r.SetRoutes()
	handlers.Auth.StartCleanUp()

	log.Printf("conductor oauth server is running on port %s", config.Port)
	log.Fatal(r.Run(":" + config.Port))
}
