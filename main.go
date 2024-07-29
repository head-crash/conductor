package main

import (
	"github.com/fastjack-it/conductor/config"
	"github.com/fastjack-it/conductor/logger"
	"github.com/fastjack-it/conductor/persistence"
	"github.com/fastjack-it/conductor/server"
)

var log = logger.Default

func main() {
	config.LoadConfig()
	log.Info("Starting Conductor OAuth Server")

	db := persistence.NewSqliteDb()
	s := server.NewServer(db)

	log.Info("conductor oauth server is running on port %s", config.Port)
	log.Fatal(s.Run(":" + config.Port))
}
