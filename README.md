# authJWT

authJWT — это минималистичный сервер авторизации на Go, реализующий выдачу и обновление JWT-токенов с использованием access и refresh пар. Проект демонстрирует принципы безопасной аутентификации, хранения refresh-токенов и защиты по IP-адресу.

## Основной функционал

- Выдача пары access/refresh токенов
- Хранение refresh-токенов в базе данных с bcrypt-хешированием
- Проверка IP-адреса клиента при обновлении токенов
- JWT-токены подписаны алгоритмом HMAC SHA256 (HS256)
- Обработка jti для защиты от повторного использования refresh-токенов

## Стек технологий

- Go
- PostgreSQL
- Gorilla Mux
- golang-jwt/jwt
- bcrypt
- стандартная библиотека

## Структура проекта

```

authJWT/
├── db/            // Подключение к БД и работа с токенами
├── handlers/      // HTTP-обработчики: выдача и обновление токенов
├── models/        // Модели для JSON
├── main.go        // Точка входа
├── go.mod / sum   // Зависимости

````

## Таблицы в базе данных

> Требуется таблица `users`, содержащая как минимум поле `guid INTEGER PRIMARY KEY`.

`refresh_tokens` создаётся автоматически при первом запуске:

```sql
CREATE TABLE IF NOT EXISTS refresh_tokens (
  guid INTEGER NOT NULL,
  refresh_hash TEXT NOT NULL,
  jti TEXT NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  PRIMARY KEY (guid, jti),
  FOREIGN KEY (guid) REFERENCES users(guid) ON DELETE CASCADE
);
````

## Установка и запуск

1. Настройте PostgreSQL и создайте базу данных `auth_db`, таблицу `users`
2. Обновите параметры подключения в `db/db.go` (хост, порт, логин, пароль)
3. Установите зависимости:

```bash
go mod tidy
```

4. Запустите сервер:

```bash
go run main.go
```

Сервер стартует на `localhost:8080`

## Маршруты

### `POST /tokens?guid=123`

Выдаёт пару `access_token` и `refresh_token` для существующего пользователя.

Ответ:

```json
{
  "access_token": "string",
  "refresh_token": "string"
}
```

### `POST /refresh`

Тело запроса:

```json
{
  "access_token": "string",
  "refresh_token": "string"
}
```

Ответ:

```json
{
  "access_token": "new string",
  "refresh_token": "new string"
}
```

## Принцип работы

* Access-токен действителен 15 минут, содержит IP-адрес, jti и guid
* Refresh-токен хранится в базе в виде bcrypt-хэша и привязан к jti
* При обновлении:

  * сравнивается IP
  * проверяется совпадение refresh по bcrypt
  * старый токен удаляется
  * создаётся новый jti и сохраняется новая пара
