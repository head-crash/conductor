package persistence

import (
	"database/sql"
	"fmt"

	"github.com/head-crash/conductor/config"
	"github.com/head-crash/conductor/models"
	"github.com/head-crash/logger"
	_ "github.com/mattn/go-sqlite3"
)

var log = logger.Default

type Sqlite struct {
	client *sql.DB
}

func NewSqliteDb() *Sqlite {
	var err error
	var client *sql.DB
	client, err = sql.Open("sqlite3", config.DbFilePath)
	if err != nil {
		log.Fatalln(err)
	}
	var DB = Sqlite{client}
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
		redirectUrl TEXT
	);`
	_, err = DB.client.Exec(createTableQuery)
	if err != nil {
		log.Fatalln(err)
	}
	return &DB
}

func (db *Sqlite) GetUserById(userId string) (*models.UserAccount, error) {
	user := &models.UserAccount{}
	query := `
		SELECT uuid, password, email, role
		FROM users
		WHERE uuid=?;`
	err := db.client.QueryRow(query, userId).
		Scan(&user.Uuid, &user.Password, &user.Email, &user.Role)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("user table query error: %v", err)
	}
	return user, nil
}

func (db *Sqlite) GetUserByEmail(email string) (*models.UserAccount, error) {
	user := &models.UserAccount{}
	query := `
		SELECT uuid, password, email, role
		FROM users
		WHERE email=?;`
	err := db.client.QueryRow(query, email).
		Scan(&user.Uuid, &user.Password, &user.Email, &user.Role)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("user table query error: %v", err)
	}
	return user, nil
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

func (db *Sqlite) GetUsers(offset, limit int) ([]*models.UserAccountOutput, error) {
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 {
		limit = 100
	}

	query := `
	SELECT uuid, email, role
	FROM users
	LIMIT ? OFFSET ?;`
	rows, err := db.client.Query(query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("users table query error: %v", err)
	}
	defer rows.Close()

	var users []*models.UserAccountOutput
	for rows.Next() {
		user := &models.UserAccountOutput{}
		err := rows.Scan(&user.Uuid, &user.Email, &user.Role)
		if err != nil {
			return nil, fmt.Errorf("error scanning user row: %v", err)
		}
		users = append(users, user)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %v", err)
	}

	return users, nil
}

func (db *Sqlite) GetClientById(clientId string) (*models.Client, error) {
	query := `
		SELECT clientId, secret, redirectUrl
		FROM clients
		WHERE clientId=?;`
	client := &models.Client{}
	err := db.client.QueryRow(query, clientId).
		Scan(&client.Id, &client.Secret, &client.RedirectUrl)
	if err != nil {
		if err == sql.ErrNoRows {
			log.Error("No rows found for client: %s with error: %s", clientId, err)
			return nil, nil
		}
		return nil, fmt.Errorf("client table query error: %v", err)
	}
	return client, nil
}

func (db *Sqlite) CreateClient(c *models.Client) error {
	query := `
	INSERT INTO clients (clientId, secret, redirectUrl)
	VALUES (?, ?, ?);`
	_, err := db.client.Exec(query, c.Id, c.Secret, c.RedirectUrl)
	return err
}

func (db *Sqlite) UpdateClient(c *models.Client) error {
	query := `
	UPDATE clients
	SET secret = ?, redirectUrl = ?
	WHERE clientId = ?;`
	_, err := db.client.Exec(query, c.Secret, c.RedirectUrl, c.Id)
	return err
}

func (db *Sqlite) DeleteClient(clientID string) error {
	query := `
	DELETE FROM clients
	WHERE clientId = ?;`
	_, err := db.client.Exec(query, clientID)
	return err
}

func (db *Sqlite) GetClients(offset, limit int) ([]*models.ClientOutput, error) {
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 {
		limit = 100
	}

	query := `
	SELECT clientId, redirectUrl
	FROM clients
	LIMIT ? OFFSET ?;`
	rows, err := db.client.Query(query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("clients table query error: %v", err)
	}
	defer rows.Close()

	var clients []*models.ClientOutput
	for rows.Next() {
		client := &models.ClientOutput{}
		err := rows.Scan(&client.Id, &client.RedirectUrl)
		if err != nil {
			return nil, fmt.Errorf("error scanning client row: %v", err)
		}
		clients = append(clients, client)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %v", err)
	}

	return clients, nil
}
