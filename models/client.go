package models

type Client struct {
	Id          string `json:"clientId"`
	Secret      string `json:"secret"`
	RedirectUri string `json:"redirectUri"`
}
