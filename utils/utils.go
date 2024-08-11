package utils

import (
	"fmt"
	"net/smtp"
	"os"
	"strconv"

	"github.com/head-crash/conductor/models"
	"github.com/head-crash/logger"
)

var log = logger.Default

// Include checks if a specific element is present in a slice of strings.
// It returns true if the element is found, otherwise false.
func Include(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// findStringIndex returns the index of the target string in the slice,
// or -1 if the string is not found.
func FindStringIndex(slice []string, target string) int {
	for i, v := range slice {
		if v == target {
			return i
		}
	}
	return -1
}

// GetEnvOrDef returns the value of an environment variable if it exists, otherwise it calls the def () string function.
func GetEnvOrDef(env string, def func() string) string {
	value, exists := os.LookupEnv(env)
	if !exists {
		log.Info("Missing env var %s", env)
		log.Debug("Using default value: %s", def())
		return def()
	}
	return value
}

func DefaultStringFunc(value string) func() string {
	return func() string { return value }
}

type StrToIntParams struct {
	Value    string
	Fallback string
}

func StringToIntenger(p StrToIntParams) int {
	i, err := strconv.Atoi(p.Value)
	if err != nil {
		return StringToIntenger(StrToIntParams{Value: p.Fallback})
	}
	return i
}

func StrToInt(number string) int {
	return StringToIntenger(StrToIntParams{Value: number, Fallback: "-1"})
}

func SendMail(smtpConfig models.SmtpConfig, recipient, subject, body string) error {

	auth := smtp.PlainAuth("", smtpConfig.User, smtpConfig.Password, smtpConfig.Host)

	// Compose the email
	to := []string{recipient}
	msg := []byte(fmt.Sprintf("To: %s\r\nSubject: %s\r\n\r\n%s\r\n", recipient, subject, body))

	// Send the email
	if err := smtp.SendMail(fmt.Sprintf("%s:%d", smtpConfig.Host, smtpConfig.Port), auth, smtpConfig.User, to, msg); err != nil {
		return fmt.Errorf("error sending email: %s", err)
	}
	return nil
}
