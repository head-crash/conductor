package main

import (
	"log"

	"github.com/fastjack-it/conductor/config"
	"github.com/fastjack-it/conductor/persistence"
	"github.com/fastjack-it/conductor/server"
)

func main() {
	config.LoadConfig()
	log.Println("Starting Conductor OAuth Server")

	db := persistence.NewSqliteDb()
	s := server.NewServer(db)

	log.Printf("conductor oauth server is running on port %s", config.Port)
	log.Fatal(s.Run(":" + config.Port))
}
