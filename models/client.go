package models

type Client struct {
	ClientId    string `json:"clientId"`
	Secret      string `json:"secret"`
	RedirectUri string `json:"redirectUri"`
}
