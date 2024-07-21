package database

import (
	"database/sql"
	"log"

	"github.com/fastjack-it/conductor/models"
	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

func InitDB() {
	var err error
	db, err = sql.Open("sqlite3", "./local.db")
	if err != nil {
		log.Fatalln(err)
	}

	// Create users table if it doesn't exist
	createTableQuery := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT,
		password TEXT,
		email TEXT,
		role TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);`
	_, err = db.Exec(createTableQuery)
	if err != nil {
		log.Fatalln(err)
	}
}

func GetUser(userID string) (*models.UserAccount, error) {
	query := `
	SELECT id, username, password, email, role, created_at
	FROM users
	WHERE id = ?`
	row := db.QueryRow(query, userID)

	var user models.UserAccount
	err := row.Scan(&user.Id, &user.Username, &user.Password, &user.Email, &user.Role)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}

func CreateUser(u *models.UserAccount) error {
	query := `
	INSERT INTO users (username, password, email, role)
	VALUES (?, ?, ?, ?);`
	_, err := db.Exec(query, u.Username, u.Password, u.Email, u.Role)
	return err
}

func UpdateUser(u *models.UserAccount) error {
	query := `
	UPDATE users
	SET username = ?, password = ?, email = ?, role = ?
	WHERE id = ?;`
	_, err := db.Exec(query, u.Username, u.Password, u.Email, u.Role, u.Id)
	return err
}
