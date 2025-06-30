
# AuthJWT

`AuthJWT` — это микросервис аутентификации и авторизации, реализующий выдачу, обновление и деавторизацию JWT-токенов. Поддерживается работа с access/refresh токенами, верификация IP и User-Agent клиента, а также webhook-оповещения при подозрительной активности.

## Особенности

- Генерация пары токенов `access + refresh` с привязкой к IP и User-Agent
- Обновление access-токена по refresh-токену
- Защита от подмены User-Agent и IP
- Удаление refresh-токена (logout)
- Поддержка Swagger-документации
- Docker-сборка и запуск через `docker-compose`

## Эндпоинты API

| Метод | Путь       | Описание                                      |
|-------|------------|-----------------------------------------------|
| POST  | `/tokens`  | Получить новую пару токенов по GUID          |
| POST  | `/refresh` | Обновить токены по refresh-токену            |
| GET   | `/whoami`  | Получить текущий GUID по access-токену       |
| POST  | `/logout`  | Деавторизация, удаление refresh-токена       |

## Документация API

Swagger-документация доступна по адресу:

```

[http://localhost:8080/swagger/index.html](http://localhost:8080/swagger/index.html)

````

Включает описание:
- Структур запросов и ответов
- Возможных кодов ошибок
- Примеров тел запросов и ответов

## Запуск

### Требования

- Go 1.20+
- Docker и Docker Compose
- PostgreSQL

### Сборка и запуск

```bash
docker-compose up --build -d
````

Приложение будет доступно на `http://localhost:8080`.

### Переменные окружения

| Переменная         | Описание                                                        |
|--------------------|-----------------------------------------------------------------|
| `WEBHOOK_URL`      | URL, на который отправляются POST-запросы при смене IP         |
| `JWT_SECRET`       | Секретный ключ для подписи JWT-токенов (в base64 или строка)   |
| `DB_HOST`          | Адрес хоста базы данных                                        |
| `DB_PORT`          | Порт PostgreSQL                                                |
| `DB_USER`          | Имя пользователя БД                                            |
| `DB_PASSWORD`      | Пароль пользователя БД                                         |
| `DB_NAME`          | Название базы данных                                           |

#### Пример `.env` файла:

```env
WEBHOOK_URL=https://example.com/webhook
JWT_SECRET=my_secret_key
DB_HOST=postgres
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=postgres
DB_NAME=auth_db

## Структура проекта

```
authJWT/
├── cmd/             # main.go
├── handlers/        # HTTP-обработчики
├── models/          # Структуры данных
├── db/              # Работа с БД
├── docs/            # Swagger-документация
├── Dockerfile
├── docker-compose.yml
└── README.md
```