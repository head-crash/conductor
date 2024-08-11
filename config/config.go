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

// log is the default logger instance
var log = logger.Default

// Configuration variables
var (
	Title         string            // Title of the application
	SecretKey     string            // Secret key for JWT signing
	DbFilePath    string            // Path to the SQLite database file
	ExpirySeconds int               // Token expiry time in seconds
	Port          string            // Port on which the server runs
	EndpointUrl   string            // URL of the server endpoint
	AuthTimeOut   int               // Authentication timeout in seconds
	MainTemplate  string            // Main HTML template content
	Loglevel      logger.Loglevel   // Log level for the application
	SMTPConfig    models.SmtpConfig // SMTP configuration for sending emails
	AdminUserName string            // Default admin username
)

// StrToInt converts a string to an integer using utility functions.
func StrToInt(v string) int {
	return utils.StringToIntenger(utils.StrToIntParams{Value: v})
}

// LoadConfig loads the configuration settings from environment variables and .env file.
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

	// Load main.html template
	fileContent, err := os.ReadFile("templates/main.html")
	if err != nil {
		log.Fatalf("Failed to read main.html: %v", err)
	}
	MainTemplate = string(fileContent)
}
