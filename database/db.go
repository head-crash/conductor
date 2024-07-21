package database

import (
	"database/sql"
	"log"

	"github.com/fastjack-it/conductor/config"
	"github.com/fastjack-it/conductor/models"
	_ "github.com/mattn/go-sqlite3"
)

type Sqlite struct {
	client *sql.DB
}

func Init() *Sqlite {
	var err error
	var client *sql.DB
	client, err = sql.Open("sqlite3", config.DbFilePath)
	if err != nil {
		log.Fatalln(err)
	}
	var DB = Sqlite{client: client}
	// Create users table if it doesn't exist
	createTableQuery := `
	CREATE TABLE IF NOT EXISTS users (
		uuid TEXT PRIMARY KEY,
		email TEXT UNIQUE,
		password TEXT,
		role TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	
	CREATE TABLE IF NOT EXISTS clients (
		clientId TEXT PRIMARY KEY,
		secret TEXT,
		redirectUri TEXT
	);`
	_, err = DB.client.Exec(createTableQuery)
	if err != nil {
		log.Fatalln(err)
	}
	return &DB
}

func (db *Sqlite) GetUserById(userID string) (*models.UserAccount, error) {
	query := `
SELECT uuid, password, email, role, created_at
FROM users
WHERE uuid = ?`
	row := db.client.QueryRow(query, userID)

	var u models.UserAccount
	err := row.Scan(&u.Uuid, &u.Password, &u.Email, &u.Role)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &u, nil
}

func (db *Sqlite) GetUserByEmail(email string) (*models.UserAccount, error) {
	query := `
SELECT uuid, password, email, role, created_at
FROM users
WHERE email = ?`
	row := db.client.QueryRow(query, email)
	var u models.UserAccount
	err := row.Scan(&u.Uuid, &u.Password, &u.Email, &u.Role)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &u, nil
}

func (db *Sqlite) CreateUser(u *models.UserAccount) error {
	query := `
	INSERT INTO users (uuid, email, password, role)
	VALUES (?, ?, ?, ?);`
	_, err := db.client.Exec(query, u.Uuid, u.Email, u.Password, u.Role)
	return err
}

func (db *Sqlite) UpdateUser(u *models.UserAccount) error {
	query := `
	UPDATE users
	SET password = ?, email = ?, role = ?
	WHERE uuid = ?;`
	_, err := db.client.Exec(query, u.Password, u.Email, u.Role, u.Uuid)
	return err
}

func (db *Sqlite) DeleteUser(userID string) error {
	query := `
	DELETE FROM users
	WHERE uuid = ?;`
	_, err := db.client.Exec(query, userID)
	return err
}

func (db *Sqlite) GetClientById(clientID string) (*models.Client, error) {
	query := `
SELECT clientId, secret, redirectUri
FROM clients
WHERE clientId = ?`
	row := db.client.QueryRow(query, clientID)
	var c models.Client
	err := row.Scan(&c.ClientId, &c.Secret, &c.RedirectUri)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &c, nil
}

func (db *Sqlite) CreateClient(c *models.Client) error {
	query := `
	INSERT INTO clients (clientId, secret, redirectUri)
	VALUES (?, ?, ?);`
	_, err := db.client.Exec(query, c.ClientId, c.Secret, c.RedirectUri)
	return err
}

func (db *Sqlite) UpdateClient(c *models.Client) error {
	query := `
	UPDATE clients
	SET secret = ?, redirectUri = ?
	WHERE clientId = ?;`
	_, err := db.client.Exec(query, c.Secret, c.RedirectUri, c.ClientId)
	return err
}

func (db *Sqlite) DeleteClient(clientID string) error {
	query := `
	DELETE FROM clients
	WHERE clientId = ?;`
	_, err := db.client.Exec(query, clientID)
	return err
}
