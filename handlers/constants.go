package handlers

type ErrorMessage string

const (
	ERR_CLIENT_ID   ErrorMessage = "Invalid clientId!"
	ERR_CREDENTIALS ErrorMessage = "Invalid email or password!"
)

type TokenType string

const (
	ACCESS_TOKEN  TokenType = "access"
	REFRESH_TOKEN TokenType = "refresh"
)
