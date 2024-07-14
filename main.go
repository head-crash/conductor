package main

import (
	"log"
	"net/http"

	"github.com/fastjack-it/conductor/config"
	"github.com/fastjack-it/conductor/handlers"

	"github.com/gorilla/mux"
)

func main() {
	config.LoadConfig()

	r := mux.NewRouter()

	r.HandleFunc("/oauth/token", handlers.TokenHandler).Methods("POST")
	r.HandleFunc("/oauth/authorize", handlers.AuthorizeHandler).Methods("GET", "POST")

	log.Println("conductor is running on port 5001")
	log.Fatal(http.ListenAndServe(":5001", r))
}
