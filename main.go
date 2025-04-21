package main

import (
	"authJWT/db"
	"authJWT/handlers"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

func main() {

	err := db.InitDB()
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	router := mux.NewRouter()
	router.HandleFunc("/tokens", handlers.GiveTokens).Methods("POST")
	router.HandleFunc("/refresh", handlers.RefreshTokens).Methods("POST")

	srv := &http.Server{
		Handler:      router,
		Addr:         ":8080",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Println("Запуск сервера на localhost:8080")
	log.Fatal(srv.ListenAndServe())
}
