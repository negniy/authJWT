package db

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

const (
	host     = "localhost"
	port     = 5432
	user     = "postgres"
	password = "1"
	dbname   = "auth_db"
)

var db *sql.DB

func InitDB() error {
	connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
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
        CREATE TABLE IF NOT EXISTS refresh_tokens (
			guid INTEGER NOT NULL,
			refresh_hash TEXT NOT NULL,
			jti TEXT NOT NULL,
			expires_at TIMESTAMP NOT NULL,
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

func SaveRefreshToken(guid int, refreshHash string, jti string) error {
	_, err := db.Exec(`
		INSERT INTO refresh_tokens (guid, refresh_hash, jti, expires_at)
		VALUES ($1, $2, $3, NOW() + INTERVAL '7 days')
	`, guid, refreshHash, jti)
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

func GetUserEmail(guid int) (string, error) {
	var email string
	err := db.QueryRow(`SELECT email FROM users WHERE guid = $1`, guid).Scan(&email)
	if err != nil {
		return "", fmt.Errorf("ошибка получения email пользователя: %w", err)
	}
	return email, nil
}
