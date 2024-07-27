package models

type UserAccount struct {
	Uuid     string `json:"uuid"`
	Password string `json:"password"`
	Email    string `json:"email"`
	Role     Role   `json:"role"`
}
