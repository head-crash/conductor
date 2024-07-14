package database

import (
	"log"

	"github.com/fastjack-it/conductor/config"
	"github.com/fastjack-it/conductor/models"
	r "gopkg.in/rethinkdb/rethinkdb-go.v6"
)

var session *r.Session

func InitDB() {
	var err error
	session, err = r.Connect(r.ConnectOpts{
		Address:  config.DbEndpoint,
		Database: config.DbName,
	})
	if err != nil {
		log.Fatalln(err)
	}
}

func GetUser(userID string) (*models.UserAccount, error) {
	res, err := r.Table("users").Get(userID).Run(session)
	if err != nil {
		return nil, err
	}
	defer res.Close()

	var user models.UserAccount
	if err := res.One(&user); err != nil {
		return nil, err
	}
	return &user, nil
}

func UpsertUser(user *models.UserAccount) error {
	_, err := r.Table("users").Insert(user, r.InsertOpts{Conflict: "update"}).RunWrite(session)
	return err
}

func GetAllUsers() ([]models.UserAccount, error) {
	res, err := r.Table("users").Run(session)
	if err != nil {
		return nil, err
	}
	defer res.Close()

	var users []models.UserAccount
	if err := res.All(&users); err != nil {
		return nil, err
	}
	return users, nil
}
