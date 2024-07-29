package config

import (
	"os"

	"github.com/fastjack-it/conductor/logger"
	"github.com/fastjack-it/conductor/utils"
	"github.com/joho/godotenv"
)

var getEnvOrDef = utils.GetEnvOrDef
var DefaultString = utils.DefaultStringFunc
var log = logger.Default

var (
	SecretKey     string
	DbFilePath    string
	ExpirySeconds int
	Port          string
	EndpointUrl   string
	AuthTimeOut   int
	LoginHtml     string
	Loglevel      logger.Loglevel
)

func StrToInt(v string) int {
	return utils.StringToIntenger(utils.StrToIntParams{Value: v})
}

func LoadConfig() {
	// Load .env file if it exists
	err := godotenv.Load()
	if err == nil {
		log.Info("Found .env file will be used")
	}

	required := func() string {
		log.Fatal("Critical error: environment variable is mandatory!")
		return ""
	}

	SecretKey = getEnvOrDef("SECRET_KEY", required)
	DbFilePath = getEnvOrDef("DB_FILE_PATH", DefaultString("./conductor.db"))
	ExpirySeconds = StrToInt(getEnvOrDef("TOKEN_EXPIRY_SECONDS", DefaultString("3600")))
	Port = getEnvOrDef("PORT", DefaultString("8080"))
	EndpointUrl = getEnvOrDef("ENDPOINT_URL", DefaultString("http://localhost:"+Port))
	AuthTimeOut = StrToInt(getEnvOrDef("AUTH_TIMEOUT_SECONDS", DefaultString("300")))
	Loglevel = logger.Loglevel(getEnvOrDef("LOG_LEVEL", DefaultString("DEBUG")))

	// Set log level
	log.SetLogLevel(Loglevel)

	// Load login.html template
	fileContent, err := os.ReadFile("templates/login.html")
	if err != nil {
		log.Fatalf("Failed to read login.html: %v", err)
	}
	LoginHtml = string(fileContent)
}
