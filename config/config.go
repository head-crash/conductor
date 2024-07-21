package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

var (
	ClientID      string
	ClientSecret  string
	RedirectURI   string
	SecretKey     string
	DbEndpoint    string
	DbName        string
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

	ClientID = getEnvOrDef("CLIENT_ID", required)
	ClientSecret = getEnvOrDef("CLIENT_SECRET", required)
	RedirectURI = getEnvOrDef("REDIRECT_URI", required)
	SecretKey = getEnvOrDef("SECRET_KEY", required)
	DbEndpoint = getEnvOrDef("DB_ENDPOINT", required)
	DbName = getEnvOrDef("DB_NAME", required)
	ExpirySeconds = strToInt(getEnvOrDef("EXPIRY_SECONDS", defaultString("3600")))
}
