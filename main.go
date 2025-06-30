package main

import (
	"authJWT/db"
	"authJWT/handlers"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"

	httpSwagger "github.com/swaggo/http-swagger"

	_ "authJWT/docs"
)

// @title AuthJWT API
// @version 1.0
// @description Сервис аутентификации с JWT access и refresh токенами
// @host localhost:8080
// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name Authorization
// @BasePath /
func main() {

	err := godotenv.Load()
	if err != nil {
		log.Println("Не удалось загрузить .env")
	}

	key := os.Getenv("SECRET_KEY")
	if key == "" {
		log.Fatal("SECRET_KEY не задан в окружении")
	}

	handlers.Init([]byte(key))

	err = db.InitDB()
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	router := mux.NewRouter()
	router.HandleFunc("/tokens", handlers.GiveTokens).Methods("POST")
	router.HandleFunc("/refresh", handlers.RefreshTokens).Methods("POST")
	router.HandleFunc("/whoami", handlers.GetCurrentUser).Methods("GET")
	router.HandleFunc("/logout", handlers.Logout).Methods("POST")
	router.PathPrefix("/swagger/").Handler(httpSwagger.WrapHandler)

	srv := &http.Server{
		Handler:      router,
		Addr:         ":8080",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Println("Запуск сервера на localhost:8080")
	log.Fatal(srv.ListenAndServe())
}
