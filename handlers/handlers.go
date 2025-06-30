package handlers

import (
	"authJWT/db"
	"authJWT/models"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var secretKey []byte

func Init(k []byte) {
	secretKey = k
}

func generateAccessToken(guid int, uip string, jti string) (string, error) {
	claims := jwt.MapClaims{
		"guid": guid,
		"ip":   uip,
		"exp":  time.Now().Add(15 * time.Minute).Unix(),
		"jti":  jti,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
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

// @Summary      Получить access и refresh токены
// @Description  Возвращает новую пару токенов по GUID пользователя
// @Tags         tokens
// @Accept       json
// @Produce      json
// @Param        guid  query     string  true  "User GUID"
// @Success      200   {object}  models.Tokens
// @Failure      400   {string}  string  "Некорректный GUID"
// @Failure      500   {string}  string  "Внутренняя ошибка сервера"
// @Router       /tokens [post]
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

	userAgent := r.UserAgent()
	err = db.SaveRefreshToken(guid, string(refreshHash), jti, userAgent)
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

// @Summary      Обновить access и refresh токены
// @Description  Обновляет токены по refresh-токену из тела запроса
// @Tags         tokens
// @Accept       json
// @Produce      json
// @Param        request  body      models.Tokens  true  "Refresh Request"
// @Success      200      {object}  models.Tokens
// @Failure      400      {string}  string  "Неверный формат запроса"
// @Failure      401      {string}  string  "Ошибка авторизации"
// @Failure      500      {string}  string  "Внутренняя ошибка"
// @Router       /refresh [post]
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
		notifyWebhook(guid, tokenIP, ip)
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

	storedUA, err := db.GetUserAgent(guid, jti)
	if err != nil {
		log.Println("Ошибка получения user-agent из БД:", err)
		responseError(w, http.StatusInternalServerError, err)
		return
	}
	currentUA := r.UserAgent()

	if storedUA != currentUA {
		log.Println("User-Agent не совпадает, деавторизация")
		_ = db.DeleteRefreshToken(guid, jti)
		responseError(w, http.StatusUnauthorized, fmt.Errorf("недопустимая попытка обновления с другим User-Agent"))
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

	err = db.SaveRefreshToken(guid, string(newRefreshHash), newJTI, currentUA)
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

// @Summary      Получить информацию о текущем пользователе
// @Description  Возвращает GUID текущего пользователя по access-токену
// @Tags         user
// @Produce      json
// @Success      200  {string}  string  "GUID пользователя"
// @Failure      401  {string}  string  "Неавторизован"
// @Router       /whoami [get]
// @Security     ApiKeyAuth
func GetCurrentUser(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		log.Println("Отсутствует заголовок Authorization")
		responseError(w, http.StatusUnauthorized, fmt.Errorf("отсутствует заголовок Authorization"))
		return
	}

	tokenString := strings.TrimPrefix(auth, "Bearer ")

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			log.Println("Неправильный метод подписи")
			return nil, fmt.Errorf("неправильный метод подписи")
		}
		return secretKey, nil
	})
	if err != nil || !token.Valid {
		log.Println("Токен невалиден")
		responseError(w, http.StatusUnauthorized, fmt.Errorf("некорректный токен"))
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		log.Println("Ошибка преобразования claims в мапу")
		responseError(w, http.StatusUnauthorized, fmt.Errorf("некорректные claims"))
		return
	}

	guidFloat, ok := claims["guid"].(float64)
	if !ok {
		log.Println("Поле guid не найдено в токене")
		responseError(w, http.StatusUnauthorized, fmt.Errorf("поле guid не найдено в токене"))
		return
	}
	guid := int(guidFloat)

	response(w, http.StatusOK, map[string]int{"guid": guid})
}

// @Summary      Деавторизация
// @Description  Удаляет refresh-токен пользователя
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request  body      models.Tokens  true  "Refresh Request"
// @Success      200      {string}  string  "Выход выполнен успешно"
// @Failure      400      {string}  string  "Некорректный запрос"
// @Failure      500      {string}  string  "Ошибка удаления токена"
// @Router       /logout [post]
func Logout(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		log.Println("Отсутствует заголовок Authorization")
		responseError(w, http.StatusUnauthorized, fmt.Errorf("отсутствует заголовок Authorization"))
		return
	}

	tokenString := strings.TrimPrefix(auth, "Bearer ")

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			log.Println("Неправильный метод подписи")
			return nil, fmt.Errorf("неправильный метод подписи")
		}
		return secretKey, nil
	})
	if err != nil || !token.Valid {
		log.Println("Токен невалиден")
		responseError(w, http.StatusUnauthorized, fmt.Errorf("некорректный токен"))
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		log.Println("Ошибка преобразования claims в мапу")
		responseError(w, http.StatusUnauthorized, fmt.Errorf("некорректные claims"))
		return
	}

	guidFloat, ok := claims["guid"].(float64)
	if !ok {
		log.Println("Поле guid не найдено в токене")
		responseError(w, http.StatusUnauthorized, fmt.Errorf("поле guid не найдено в токене"))
		return
	}

	jti, ok := claims["jti"].(string)
	if !ok {
		log.Println("Поле jti не найдено в токене")
		responseError(w, http.StatusUnauthorized, fmt.Errorf("jti не найден"))
		return
	}

	err = db.DeleteRefreshToken(int(guidFloat), jti)
	if err != nil {
		log.Println("Ошибка удаления refresh токена при logout:", err)
		responseError(w, http.StatusInternalServerError, err)
		return
	}

	response(w, http.StatusOK, nil)
}

func notifyWebhook(guid int, oldIP, newIP string) {
	webhookURL := os.Getenv("WEBHOOK_URL")
	if webhookURL == "" {
		log.Println("WEBHOOK_URL не задан")
		return
	}

	body, _ := json.Marshal(map[string]interface{}{
		"guid":   guid,
		"old_ip": oldIP,
		"new_ip": newIP,
	})

	resp, err := http.Post(webhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		log.Println("Ошибка отправки webhook:", err)
		return
	}
	defer resp.Body.Close()
	log.Printf("Webhook отправлен (код %d) на %s\n", resp.StatusCode, webhookURL)
}
