package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

var (
	SecretKey     string
	DbFilePath    string
	ExpirySeconds int
)

func getEnvOrDef(env string, def func() string) string {
	value, exists := os.LookupEnv(env)
	if !exists {
		log.Printf("Missing environment variable: %s", env)
		return def()
	}
	return value
}

func LoadConfig() {
	// Load .env file if it exists
	err := godotenv.Load()
	if err == nil {
		log.Println("Found .env file will be used")
	}

	required := func() string {
		log.Fatal("Critical error: environment variable is mandatory!")
		return ""
	}

	defaultString := func(value string) func() string {
		log.Printf("Using default value: %s", value)
		return func() string { return value }
	}

	SecretKey = getEnvOrDef("SECRET_KEY", required)
	DbFilePath = getEnvOrDef("DB_FILE_PATH", defaultString("./conductor.db"))
	ExpirySeconds = strToInt(getEnvOrDef("EXPIRY_SECONDS", defaultString("3600")))
}
