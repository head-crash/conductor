package persistence

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	"github.com/head-crash/conductor/config"
	"github.com/head-crash/conductor/models"
	_ "github.com/mattn/go-sqlite3"
)

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

func (db *Sqlite) GetUserById(userID string) (*models.UserAccount, error) {
	ctx := context.Background()
	user := &models.UserAccount{}
	query := `
		SELECT uuid, password, email, role
		FROM users
		WHERE uuid=?;`
	err := db.client.QueryRowContext(ctx, query, userID).Scan(&user.Uuid, &user.Password, &user.Email, &user.Role)
	switch {
	case err == sql.ErrNoRows:
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("query error: %v", err)
	default:
		return user, nil
	}
}

func (db *Sqlite) GetUserByEmail(email string) (*models.UserAccount, error) {
	query := `
		SELECT uuid, password, email, role
		FROM users
		WHERE email='?';`
	if row, err := db.client.Query(query, email); err != nil {
		return nil, fmt.Errorf("query error: %v", err)
	} else {
		user := &models.UserAccount{}
		if err = row.Scan(&user.Uuid, &user.Password, &user.Email, &user.Role); err != nil {
			return nil, fmt.Errorf("query error: %v", err)
		}
		return user, nil
	}

	// switch {
	// case err == sql.ErrNoRows:
	// 	return nil, fmt.Errorf("query error: %v", err)
	// case err != nil:
	// 	return nil, fmt.Errorf("query error: %v", err)
	// default:
	// 	return user, nil
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

func (db *Sqlite) GetClientById(clientId string) (*models.Client, error) {
	ctx := context.Background()
	query := `
		SELECT clientId, secret, redirectUrl
		FROM clients
		WHERE clientId='?';`
	client := &models.Client{}
	err := db.client.QueryRowContext(ctx, query, clientId).Scan(&client.Id, &client.Secret, &client.RedirectUrl)
	return client, err
	// switch {
	// case err == sql.ErrNoRows:
	// 	return nil, fmt.Errorf("query error: %v", err)
	// 	//return nil, nil
	// case err != nil:
	// 	return nil, fmt.Errorf("query error: %v", err)
	// default:
	// 	return client, nil
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
