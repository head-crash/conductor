package models

// SmtpConfig represents the configuration settings for an SMTP server.
type SmtpConfig struct {
	Host     string // Host is the SMTP server address.
	Port     int    // Port is the port number for the SMTP server.
	User     string // User is the username for SMTP authentication.
	Password string // Password is the password for SMTP authentication.
}
