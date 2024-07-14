package models

type Group struct {
	Id    string   `json:"id"`
	Name  string   `json:"name"`
	Owner string   `json:"owner"`
	Users []string `json:"users"`
}

type UserAccount struct {
	Id       string   `json:"id"`
	Username string   `json:"username"`
	Password string   `json:"password"`
	Email    string   `json:"email"`
	Role     Role     `json:"role"`
	Groups   []string `json:"groups"`
}
