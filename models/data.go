package models

// Client represents an OAuth client with its ID, secret, and redirect URL.
type Client struct {
	Id          string `json:"client_id"`
	Secret      string `json:"secret"`
	RedirectUrl string `json:"redirect_url"`
}

// Role defines the role of a user in the system.
type Role string

const (
	// ADMIN represents an administrative user role.
	ADMIN Role = "ADMIN"
	// USER represents a standard user role.
	USER Role = "USER"
)

// IsValid checks if the role is a valid role (either ADMIN or USER).
func (r Role) IsValid() bool {
	switch r {
	case ADMIN, USER:
		return true
	}
	return false
}

// UserAccount represents a user account with its UUID, password, email, and role.
type UserAccount struct {
	Uuid     string `json:"uuid"`
	Password string `json:"password"`
	Email    string `json:"email"`
	Role     Role   `json:"role"`
}
