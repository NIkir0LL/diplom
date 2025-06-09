package main

import (
    "database/sql"
    "log"
    _ "github.com/mattn/go-sqlite3"
)

func initDB() *sql.DB {
    db, err := sql.Open("sqlite3", "hsm.db")
    if err != nil {
        log.Fatal("Ошибка открытия базы данных:", err)
    }
    return db
}

func createTables(db *sql.DB) {
    _, err := db.Exec(`CREATE TABLE IF NOT EXISTS items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        type TEXT NOT NULL,
        path TEXT NOT NULL,
        encrypted_data BLOB NOT NULL,
        UNIQUE(user_id, path)
    )`)
    if err != nil {
        log.Fatal("Ошибка создания таблицы:", err)
    }
}