package utils

import (
    "github.com/gorilla/sessions"
)

// Store — глобальное хранилище сессий для всего приложения
var Store = sessions.NewCookieStore([]byte("dGhpcy1pcy1hLXNlY3VyZS1rZXk="))

func init() {
    Store.Options = &sessions.Options{
        Path:     "/",           // Доступно для всего сайта
        HttpOnly: true,          // Защита от XSS
        MaxAge:   600,           // 10 минут бездействия
    }
}