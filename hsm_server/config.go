package main

import (
    "os"
    "log"
)

func loadConfig() (masterKey []byte, apiKey string) {
    var err error
    masterKey, err = os.ReadFile("master.key")
    if err != nil {
        log.Fatal("Ошибка чтения мастер-ключа:", err)
    }
    apiKey = os.Getenv("HSM_API_KEY")
    if apiKey == "" {
        log.Fatal("Переменная HSM_API_KEY не установлена")
    }
    return masterKey, apiKey
}