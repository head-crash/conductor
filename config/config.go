package config

import (
	"os"

	"github.com/head-crash/conductor/models"
	"github.com/head-crash/conductor/utils"
	"github.com/head-crash/logger"
	"github.com/joho/godotenv"
)

var getEnvOrDef = utils.GetEnvOrDef
var DefaultString = utils.DefaultStringFunc
var log = logger.Default

var (
	Title         string
	SecretKey     string
	DbFilePath    string
	ExpirySeconds int
	Port          string
	EndpointUrl   string
	AuthTimeOut   int
	MainTemplate  string
	Loglevel      logger.Loglevel
	SMTPConfig    models.SmtpConfig
	AdminUserName string
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

	// Set log level
	Loglevel = logger.Loglevel((getEnvOrDef("LOG_LEVEL", DefaultString("DEBUG"))))
	log.SetLogLevel(Loglevel)

	Title = getEnvOrDef("TITLE", DefaultString("Conductor"))
	SecretKey = getEnvOrDef("SECRET_KEY", required)
	DbFilePath = getEnvOrDef("DB_FILE_PATH", DefaultString("./conductor.db"))
	ExpirySeconds = StrToInt(getEnvOrDef("TOKEN_EXPIRY_SECONDS", DefaultString("3600")))
	Port = getEnvOrDef("PORT", DefaultString("8080"))
	EndpointUrl = getEnvOrDef("ENDPOINT_URL", DefaultString("http://localhost:"+Port))
	AuthTimeOut = StrToInt(getEnvOrDef("AUTH_TIMEOUT_SECONDS", DefaultString("300")))
	SMTPConfig.Host = getEnvOrDef("SMTP_HOST", required)
	SMTPConfig.Port = StrToInt(getEnvOrDef("SMTP_PORT", required))
	SMTPConfig.User = getEnvOrDef("SMTP_USER", required)
	SMTPConfig.Password = getEnvOrDef("SMTP_PASSWORD", required)
	AdminUserName = getEnvOrDef("ADMIN_USER_NAME", DefaultString("admin"))

	// Load login.html template
	fileContent, err := os.ReadFile("templates/main.html")
	if err != nil {
		log.Fatalf("Failed to read login.html: %v", err)
	}
	MainTemplate = string(fileContent)
}
