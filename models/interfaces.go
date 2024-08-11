package models

// Database defines the interface for database operations related to clients and users.
type Database interface {
	// CreateClient inserts a new client into the database.
	CreateClient(c *Client) error

	// CreateUser inserts a new user into the database.
	CreateUser(u *UserAccount) error

	// DeleteClient removes a client from the database by their client ID.
	DeleteClient(clientID string) error

	// DeleteUser removes a user from the database by their user ID.
	DeleteUser(userID string) error

	// GetClients retrieves a list of clients from the database with pagination.
	GetClients(offset, limit int) ([]*ClientOutput, error)

	// GetClientById retrieves a client from the database by their client ID.
	GetClientById(clientID string) (*Client, error)

	// GetUsers retrieves a list of users from the database with pagination.
	GetUsers(offset, limit int) ([]*UserAccountOutput, error)

	// GetUserById retrieves a user from the database by their user ID.
	GetUserById(userID string) (*UserAccount, error)

	// GetUserByEmail retrieves a user from the database by their email.
	GetUserByEmail(email string) (*UserAccount, error)

	// UpdateClient updates an existing client's information in the database.
	UpdateClient(c *Client) error

	// UpdateUser updates an existing user's information in the database.
	UpdateUser(u *UserAccount) error
}
