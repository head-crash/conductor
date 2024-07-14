package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

var (
	ClientID     string
	ClientSecret string
	RedirectURI  string
	SecretKey    string
	DbEndpoint   string
	DbName       string
)

func LoadConfig() {
	// Load .env file if it exists
	err := godotenv.Load()
	if err != nil {
		log.Println("No .env file found")
	}

	ClientID = os.Getenv("CLIENT_ID")
	ClientSecret = os.Getenv("CLIENT_SECRET")
	RedirectURI = os.Getenv("REDIRECT_URI")
	SecretKey = os.Getenv("SECRET_KEY")
	DbEndpoint = os.Getenv("DB_ENDPOINT")
	DbName = os.Getenv("DB_NAME")

	if ClientID == "" || ClientSecret == "" || RedirectURI == "" || SecretKey == "" {
		log.Fatal("Missing required environment variables")
	}
}
