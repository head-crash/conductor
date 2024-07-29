package models

type Client struct {
	Id          string `json:"client_id"`
	Secret      string `json:"secret"`
	RedirectUrl string `json:"redirect_url"`
}

type Role string

const (
	ADMIN Role = "ADMIN"
	USER  Role = "USER"
)

func (r Role) IsValid() bool {
	switch r {
	case ADMIN, USER:
		return true
	}
	return false
}

type UserAccount struct {
	Uuid     string `json:"uuid"`
	Password string `json:"password"`
	Email    string `json:"email"`
	Role     Role   `json:"role"`
}
