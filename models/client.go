package models

type Client struct {
	Id          string `json:"client_id"`
	Secret      string `json:"secret"`
	RedirectUrl string `json:"redirectUrl"`
}
