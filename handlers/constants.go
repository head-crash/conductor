package handlers

type EntityType string
type ErrorMessage string
type HttpMethod string

const (
	USER     EntityType = "user"
	EMAIL    EntityType = "email"
	CLIENT   EntityType = "client"
	SCOPE    EntityType = "scope"
	STATE    EntityType = "state"
	PASSWORD EntityType = "password"
	SECRET   EntityType = "secret"
	ROLE     EntityType = "role"
	ID       EntityType = "id"

	ERR_CLIENT_ID   ErrorMessage = "Invalid clientId!"
	ERR_CREDENTIALS ErrorMessage = "Invalid email or password!"

	GET    HttpMethod = "GET"
	POST   HttpMethod = "POST"
	PATCH  HttpMethod = "PATCH"
	PUT    HttpMethod = "PUT"
	DELETE HttpMethod = "DELETE"
)
