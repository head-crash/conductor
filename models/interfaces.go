package models

type Database interface {
	CreateClient(c *Client) error
	CreateUser(u *UserAccount) error
	DeleteClient(clientID string) error
	DeleteUser(userID string) error
	GetClients(offset, limit int) ([]*ClientOutput, error)
	GetClientById(clientID string) (*Client, error)
	GetUsers(offset, limit int) ([]*UserAccountOutput, error)
	GetUserById(userID string) (*UserAccount, error)
	GetUserByEmail(email string) (*UserAccount, error)
	UpdateClient(c *Client) error
	UpdateUser(u *UserAccount) error
}
