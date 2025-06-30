package db

import (
	"database/sql"
	"fmt"
	"os"

	_ "github.com/lib/pq"
)

var db *sql.DB

func InitDB() error {

	host := os.Getenv("POSTGRES_HOST")
	if host == "" {
		host = "localhost"
	}

	port := os.Getenv("POSTGRES_PORT")
	if port == "" {
		port = "5432"
	}

	user := os.Getenv("POSTGRES_USER")
	password := os.Getenv("POSTGRES_PASSWORD")
	dbname := os.Getenv("POSTGRES_DB")

	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)

	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		return err
	}

	err = db.Ping()
	if err != nil {
		return err
	}

	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS users (
		guid INTEGER PRIMARY KEY,
		email TEXT
	);
`)
	if err != nil {
		return err
	}

	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS refresh_tokens (
		guid INTEGER NOT NULL,
		refresh_hash TEXT NOT NULL,
		jti TEXT NOT NULL,
		expires_at TIMESTAMP NOT NULL,
		user_agent TEXT NOT NULL,
		PRIMARY KEY (guid, jti),
		FOREIGN KEY (guid) REFERENCES users(guid) ON DELETE CASCADE
	);
`)
	return err
}

func CheckUID(guid int) error {
	var exists bool
	err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM users WHERE guid = $1)`, guid).Scan(&exists)
	if err != nil {
		return fmt.Errorf("ошибка проверки пользователя: %w", err)
	}
	if !exists {
		return fmt.Errorf("пользователь с таким guid не найден")
	}
	return nil
}

func SaveRefreshToken(guid int, refreshHash string, jti string, userAgent string) error {
	_, err := db.Exec(`
		INSERT INTO refresh_tokens (guid, refresh_hash, jti, expires_at, user_agent)
		VALUES ($1, $2, $3, NOW() + INTERVAL '7 days', $4)
	`, guid, refreshHash, jti, userAgent)
	if err != nil {
		return fmt.Errorf("ошибка сохранения refresh токена: %w", err)
	}
	return nil
}

func GetRefreshTokenHash(guid int, jti string) (string, error) {
	var refreshHash string
	err := db.QueryRow(`
		SELECT refresh_hash FROM refresh_tokens
		WHERE guid = $1 AND jti = $2
	`, guid, jti).Scan(&refreshHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("refresh токен не найден")
		}
		return "", fmt.Errorf("ошибка поиска refresh токена: %w", err)
	}
	return refreshHash, nil
}

func DeleteRefreshToken(guid int, jti string) error {
	_, err := db.Exec(`
		DELETE FROM refresh_tokens
		WHERE guid = $1 AND jti = $2
	`, guid, jti)
	if err != nil {
		return fmt.Errorf("ошибка удаления refresh токена: %w", err)
	}
	return nil
}

func GetUserAgent(guid int, jti string) (string, error) {
	var userAgent string
	err := db.QueryRow(`
		SELECT user_agent FROM refresh_tokens
		WHERE guid = $1 AND jti = $2
	`, guid, jti).Scan(&userAgent)
	if err != nil {
		return "", fmt.Errorf("ошибка получения user-agent: %w", err)
	}
	return userAgent, nil
}
