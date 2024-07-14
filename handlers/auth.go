package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/fastjack-it/conductor/config"
	"github.com/fastjack-it/conductor/utils"
)

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

func TokenHandler(w http.ResponseWriter, r *http.Request) {

	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	if clientID != config.ClientID || clientSecret != config.ClientSecret {
		http.Error(w, "Invalid client credentials", http.StatusUnauthorized)
		return
	}

	accessToken, err := utils.GenerateToken(clientID, "access", 3600)
	if err != nil {
		http.Error(w, "Failed to generate access token", http.StatusInternalServerError)
		return
	}

	refreshToken, err := utils.GenerateToken(clientID, "refresh", 7200)
	if err != nil {
		http.Error(w, "Failed to generate refresh token", http.StatusInternalServerError)
		return
	}

	response := TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "bearer",
		RefreshToken: refreshToken,
		ExpiresIn:    3600,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func AuthorizeHandler(w http.ResponseWriter, r *http.Request) {
}
