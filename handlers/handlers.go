package handlers

import (
	"authJWT/db"
	"authJWT/models"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var secretKey = []byte("my_secret_key")

func generateAccessToken(guid int, uip string, jti string) (string, error) {
	claims := jwt.MapClaims{
		"guid": guid,
		"ip":   uip,
		"exp":  time.Now().Add(15 * time.Minute).Unix(),
		"jti":  jti,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secretKey)
}

func generateRefreshToken() (string, error) {
	refreshTokenBytes := make([]byte, 32)
	_, err := rand.Read(refreshTokenBytes)
	if err != nil {
		return "", err
	}
	refreshToken := base64.StdEncoding.EncodeToString(refreshTokenBytes)
	return refreshToken, nil
}

func response(w http.ResponseWriter, code int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if data != nil {
		err := json.NewEncoder(w).Encode(data)
		if err != nil {
			log.Println("Ошибка кодирования ответа: ", err)
		}
	}
}

func responseError(w http.ResponseWriter, code int, err error) {
	response(w, code, map[string]string{"error": err.Error()})
}

func GiveTokens(w http.ResponseWriter, r *http.Request) {
	str_guid := r.URL.Query().Get("guid")

	guid, err := strconv.Atoi(str_guid)
	if err != nil {
		log.Println("Ошибка парсинга guid")
		responseError(w, http.StatusBadRequest, err)
		return
	}
	err = db.CheckUID(guid)
	if err != nil {
		log.Println("Ошибка нет пользователя с таким id")
		responseError(w, http.StatusBadRequest, err)
		return
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		log.Println("Ошибка получения ip")
		responseError(w, http.StatusBadRequest, err)
		return
	}

	bytes := make([]byte, 16)
	_, err = rand.Read(bytes)
	if err != nil {
		log.Println("Ошибка генерации jti")
		responseError(w, http.StatusInternalServerError, err)
		return
	}
	jti := base64.URLEncoding.EncodeToString(bytes)

	access, err := generateAccessToken(guid, ip, jti)
	if err != nil {
		log.Println("Ошибка генерации access-token")
		responseError(w, http.StatusInternalServerError, err)
		return
	}
	refresh, err := generateRefreshToken()
	if err != nil {
		log.Println("Ошибка генерации refresh-token")
		responseError(w, http.StatusInternalServerError, err)
		return
	}
	refreshHash, err := bcrypt.GenerateFromPassword([]byte(refresh), bcrypt.DefaultCost)
	if err != nil {
		log.Println("Ошибка хеширования refresh-token")
		responseError(w, http.StatusInternalServerError, err)
		return
	}

	err = db.SaveRefreshToken(guid, string(refreshHash), jti)
	if err != nil {
		log.Println("Ошибка сохрания в бд token`ов")
		responseError(w, http.StatusInternalServerError, err)
		return
	}
	response(w, http.StatusOK, models.Tokens{
		AccessToken:  access,
		RefreshToken: refresh,
	})
}

func RefreshTokens(w http.ResponseWriter, r *http.Request) {
	var req models.Tokens
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Println("Ошибка декодирования запроса")
		responseError(w, http.StatusBadRequest, err)
		return
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		log.Println("Ошибка получения ip")
		responseError(w, http.StatusBadRequest, err)
		return
	}

	token, err := jwt.Parse(req.AccessToken, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, fmt.Errorf("неправильный метод подписи")
		}
		return secretKey, nil
	})
	if err != nil {
		log.Println("Ошибка парсинга access-token")
		responseError(w, http.StatusUnauthorized, err)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		log.Println("Невалидный access-token")
		responseError(w, http.StatusUnauthorized, fmt.Errorf("invalid access token"))
		return
	}

	guidFloat, ok := claims["guid"].(float64)
	if !ok {
		log.Println("Ошибка получения guid из токена")
		responseError(w, http.StatusUnauthorized, fmt.Errorf("invalid access token"))
		return
	}
	guid := int(guidFloat)

	tokenIP, ok := claims["ip"].(string)
	if !ok {
		log.Println("Ошибка получения ip из токена")
		responseError(w, http.StatusUnauthorized, fmt.Errorf("invalid access token"))
		return
	}
	if tokenIP != ip {
		log.Println("IP адреса не совпадают")
		email, err := db.GetUserEmail(guid)
		if err != nil {
			log.Println("Ошибка получения email пользователя:", err)
		} else {
			log.Printf("Warning: отправлено письмо на %s о смене IP (старый IP: %s, новый IP: %s)\n", email, tokenIP, ip)
		}
	}

	jti, ok := claims["jti"].(string)
	if !ok {
		log.Println("Ошибка получения jti из токена")
		responseError(w, http.StatusUnauthorized, fmt.Errorf("invalid access token"))
		return
	}

	storedHash, err := db.GetRefreshTokenHash(guid, jti)
	if err != nil {
		log.Println(guid, jti)
		log.Println("Ошибка поиска refresh-token в бд")
		responseError(w, http.StatusUnauthorized, err)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(req.RefreshToken))
	if err != nil {
		log.Println("Refresh токен не совпадает")
		responseError(w, http.StatusUnauthorized, fmt.Errorf("invalid refresh token"))
		return
	}

	err = db.DeleteRefreshToken(guid, jti)
	if err != nil {
		log.Println("Ошибка удаления старого refresh токена")
		responseError(w, http.StatusInternalServerError, err)
		return
	}

	bytes := make([]byte, 16)
	_, err = rand.Read(bytes)
	if err != nil {
		log.Println("Ошибка генерации нового jti")
		responseError(w, http.StatusInternalServerError, err)
		return
	}
	newJTI := base64.StdEncoding.EncodeToString(bytes)

	newAccess, err := generateAccessToken(guid, ip, newJTI)
	if err != nil {
		log.Println("Ошибка генерации нового access-token")
		responseError(w, http.StatusInternalServerError, err)
		return
	}
	newRefresh, err := generateRefreshToken()
	if err != nil {
		log.Println("Ошибка генерации нового refresh-token")
		responseError(w, http.StatusInternalServerError, err)
		return
	}
	newRefreshHash, err := bcrypt.GenerateFromPassword([]byte(newRefresh), bcrypt.DefaultCost)
	if err != nil {
		log.Println("Ошибка хеширования нового refresh-token")
		responseError(w, http.StatusInternalServerError, err)
		return
	}

	err = db.SaveRefreshToken(guid, string(newRefreshHash), newJTI)
	if err != nil {
		log.Println("Ошибка сохрания нового refresh токена в бд")
		responseError(w, http.StatusInternalServerError, err)
		return
	}

	response(w, http.StatusOK, models.Tokens{
		AccessToken:  newAccess,
		RefreshToken: newRefresh,
	})

}
