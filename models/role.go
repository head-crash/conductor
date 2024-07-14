package models

type Role string

const (
	Admin Role = "ADMIN"
	User  Role = "USER"
)

func (r Role) IsValid() bool {
	switch r {
	case Admin, User:
		return true
	}
	return false
}
