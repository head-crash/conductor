package main

import (
	"log"

	"github.com/fastjack-it/conductor/config"
	"github.com/fastjack-it/conductor/router"
)

func main() {
	config.LoadConfig()
	r := router.Init()
	r.SetRoutes()

	log.Printf("OAuth server is running on port %s", config.Port)
	log.Fatal(r.Run(`:${config.Port}`))
}
