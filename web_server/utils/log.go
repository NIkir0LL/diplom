package utils

import (
    "database/sql"
    "log"
    "os"
    "path/filepath"
    "strings"
    "sync"
    "time"
)

var (
    logger     *log.Logger
    logFile    *os.File
    currentDate string
    mu         sync.Mutex
)

// initLogger инициализирует логгер для записи в файл
func initLogger() error {
    mu.Lock()
    defer mu.Unlock()

    today := time.Now().Format("2006-01-02")
    if today != currentDate {
        if logFile != nil {
            logFile.Close()
        }

        if err := os.MkdirAll("logs", 0755); err != nil {
            return err
        }

        logPath := filepath.Join("logs", today+".log")
        file, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
        if err != nil {
            return err
        }

        logFile = file
        currentDate = today
        logger = log.New(file, "", log.LstdFlags)
    }
    return nil
}

func LogAction(db *sql.DB, userID int, action string, details string) {
    if err := initLogger(); err != nil {
        log.Printf("Ошибка инициализации логгера: %v", err)
    }

    // Для неавторизованных пользователей используем UserID: -1
    logUserID := userID
    if userID <= 0 {
        logUserID = -1
    }

    // Упрощённая запись в файл
    mu.Lock()
    logger.Printf("UserID: %d | Action: %s | Details: %s", logUserID, action, details)
    mu.Unlock()

    // Запись в БД только для авторизованных пользователей и ключевых действий
    if userID > 0 {
        importantActions := map[string]bool{
            "login_success":           true,
            "logout_success":          true,
            "add_user_success":        true,
            "edit_user_success":       true,
            "update_user_success":     true,
            "delete_user_success":     true,
            "verify_document_success": true,
            "sign_document_success":   true,
            "search_users_success":    true,
            "view_home_success":       true,
            "view_logs_success":       true,
        }

        if importantActions[action] {
            _, err := db.Exec("INSERT INTO logs (user_id, action, details, created_at) VALUES (?, ?, ?, ?)",
                userID, action, details, time.Now())
            if err != nil {
                log.Printf("Ошибка записи лога в БД: %v", err)
                mu.Lock()
                logger.Printf("UserID: %d | Action: db_error | Details: Ошибка записи в БД: %v", userID, err)
                mu.Unlock()
            }
        }
    }
}

func Join(elements []string, sep string) string {
    return strings.Join(elements, sep)
}