package main

import (
	"github.com/head-crash/conductor/config"
	"github.com/head-crash/conductor/persistence"
	"github.com/head-crash/conductor/server"
	"github.com/head-crash/logger"
)

// log is the default logger instance
var log = logger.Default

// main is the entry point of the Conductor OAuth Server application
func main() {
	// LoadConfig loads the configuration settings
	config.LoadConfig()
	log.Info("Starting Conductor OAuth Server")

	// NewSqliteDb initializes a new SQLite database connection
	db := persistence.NewSqliteDb()

	// NewServer creates a new server instance with the database connection
	s := server.NewServer(db)

	// Log the server start message with the configured port
	log.Info("conductor oauth server is running on port %s", config.Port)

	// Run starts the server on the specified port and logs a fatal error if it fails
	log.Fatal(s.Run(":" + config.Port))
}
