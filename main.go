package main

import (
	"github.com/head-crash/conductor/config"
	"github.com/head-crash/conductor/logger"
	"github.com/head-crash/conductor/persistence"
	"github.com/head-crash/conductor/server"
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
