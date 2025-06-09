package handlers

import (
    "fmt"
    "html/template"
    "myproject/models"
    "myproject/utils"
    "net/http"
    "strconv"
    "strings"
)

func LogsHandler(w http.ResponseWriter, r *http.Request) {
    session, _ := utils.Store.Get(r, "alert-session")
    userID, ok := r.Context().Value("userID").(int)
    if !ok {
        utils.LogAction(utils.DB, 1, "error", "Ошибка получения userID из контекста")
        http.Error(w, "Ошибка авторизации", http.StatusUnauthorized)
        return
    }
    role, ok := r.Context().Value("role").(string)
    if !ok {
        utils.LogAction(utils.DB, userID, "error", "Ошибка получения role из контекста")
        http.Error(w, "Ошибка авторизации", http.StatusUnauthorized)
        return
    }

    utils.LogAction(utils.DB, userID, "view_logs_attempt", fmt.Sprintf("Попытка просмотра логов, role=%s", role))

    userIDQuery := r.URL.Query().Get("user_id")
    actionQuery := r.URL.Query().Get("action")
    detailsQuery := r.URL.Query().Get("details")
    startDate := r.URL.Query().Get("startDate")
    endDate := r.URL.Query().Get("endDate")

    var logs []models.Log
    var err error

    isEmptySearch := userIDQuery == "" && actionQuery == "" && detailsQuery == "" && startDate == "" && endDate == ""

    if isEmptySearch {
        if role == "admin" {
            logs, err = getAllLogs()
        } else {
            logs, err = getUserLogs(userID)
        }
        if err == nil {
            utils.LogAction(utils.DB, userID, "view_logs_success", fmt.Sprintf("Успешно получено %d логов без фильтров, role=%s", len(logs), role))
        }
    } else {
        if role == "admin" {
            logs, err = searchLogs(userIDQuery, actionQuery, detailsQuery, startDate, endDate)
        } else {
            logs, err = searchUserLogs(userID, userIDQuery, actionQuery, detailsQuery, startDate, endDate)
        }

        if err == nil {
            if len(logs) == 0 {
                utils.LogAction(utils.DB, userID, "view_logs_empty", fmt.Sprintf("Логи по критериям не найдены: user_id=%s, action=%s, details=%s, startDate=%s, endDate=%s", userIDQuery, actionQuery, detailsQuery, startDate, endDate))
                session.Values["alert"] = "Логи по заданным критериям не найдены"
                session.Values["alertType"] = "danger"
            } else {
                utils.LogAction(utils.DB, userID, "view_logs_success", fmt.Sprintf("Найдено %d логов по критериям: user_id=%s, action=%s, details=%s, startDate=%s, endDate=%s", len(logs), userIDQuery, actionQuery, detailsQuery, startDate, endDate))
            }
        }
    }

    if err != nil {
        utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка получения логов: %v", err))
        http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
        return
    }

    alert, hasAlert := session.Values["alert"].(string)
    alertType, _ := session.Values["alertType"].(string)
    if hasAlert {
        utils.LogAction(utils.DB, userID, "display_alert", fmt.Sprintf("Отображение алерта на странице логов: %s", alert))
        delete(session.Values, "alert")
        delete(session.Values, "alertType")
        session.Save(r, w)
    }

    tmpl, err := template.ParseFiles("templates/logs.html")
    if err != nil {
        utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка парсинга шаблона logs.html: %v", err))
        http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
        return
    }

    data := struct {
        Logs         []models.Log
        UserIDQuery  string
        ActionQuery  string
        DetailsQuery string
        StartDate    string
        EndDate      string
        Alert        string
        AlertType    string
        HasAlert     bool
    }{
        Logs:         logs,
        UserIDQuery:  userIDQuery,
        ActionQuery:  actionQuery,
        DetailsQuery: detailsQuery,
        StartDate:    startDate,
        EndDate:      endDate,
        Alert:        alert,
        AlertType:    alertType,
        HasAlert:     hasAlert,
    }

    err = tmpl.Execute(w, data)
    if err != nil {
        utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка выполнения шаблона logs.html: %v", err))
        http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
        return
    }

    utils.LogAction(utils.DB, userID, "render_logs_success", fmt.Sprintf("Успешный рендеринг страницы логов, %d записей", len(logs)))
}

func getAllLogs() ([]models.Log, error) {
    rows, err := utils.DB.Query("SELECT id, user_id, action, details, created_at FROM logs")
    if err != nil {
        utils.LogAction(utils.DB, 1, "error", fmt.Sprintf("Ошибка получения всех логов: %v", err))
        return nil, err
    }
    defer rows.Close()

    var logs []models.Log
    for rows.Next() {
        var log models.Log
        err := rows.Scan(&log.ID, &log.UserID, &log.Action, &log.Details, &log.CreatedAt)
        if err != nil {
            utils.LogAction(utils.DB, 1, "error", fmt.Sprintf("Ошибка сканирования логов: %v", err))
            continue
        }
        logs = append(logs, log)
    }
    if err = rows.Err(); err != nil {
        utils.LogAction(utils.DB, 1, "error", fmt.Sprintf("Ошибка обработки логов: %v", err))
        return nil, err
    }
    return logs, nil
}

func getUserLogs(userID int) ([]models.Log, error) {
    rows, err := utils.DB.Query("SELECT id, user_id, action, details, created_at FROM logs WHERE user_id = ?", userID)
    if err != nil {
        utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка получения логов пользователя userID=%d: %v", userID, err))
        return nil, err
    }
    defer rows.Close()

    var logs []models.Log
    for rows.Next() {
        var log models.Log
        err := rows.Scan(&log.ID, &log.UserID, &log.Action, &log.Details, &log.CreatedAt)
        if err != nil {
            utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка сканирования логов пользователя userID=%d: %v", userID, err))
            continue
        }
        logs = append(logs, log)
    }
    if err = rows.Err(); err != nil {
        utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка обработки логов пользователя userID=%d: %v", userID, err))
        return nil, err
    }
    return logs, nil
}

func searchLogs(userIDQuery, actionQuery, detailsQuery, startDate, endDate string) ([]models.Log, error) {
    var conditions []string
    var args []interface{}

    if userIDQuery != "" {
        if _, err := strconv.Atoi(userIDQuery); err == nil {
            conditions = append(conditions, "user_id = ?")
            args = append(args, userIDQuery)
        }
    }

    if actionQuery != "" {
        conditions = append(conditions, "action LIKE ?")
        args = append(args, "%"+actionQuery+"%")
    }

    if detailsQuery != "" {
        conditions = append(conditions, "details LIKE ?")
        args = append(args, "%"+detailsQuery+"%")
    }

    if startDate != "" && endDate != "" {
        conditions = append(conditions, "created_at BETWEEN ? AND ?")
        args = append(args, startDate, endDate)
    } else {
        if startDate != "" {
            conditions = append(conditions, "created_at >= ?")
            args = append(args, startDate)
        }
        if endDate != "" {
            conditions = append(conditions, "created_at <= ?")
            args = append(args, endDate)
        }
    }

    baseQuery := "SELECT id, user_id, action, details, created_at FROM logs"
    if len(conditions) > 0 {
        baseQuery += " WHERE " + strings.Join(conditions, " AND ")
    }

    rows, err := utils.DB.Query(baseQuery, args...)
    if err != nil {
        utils.LogAction(utils.DB, 1, "error", fmt.Sprintf("Ошибка поиска логов: %v", err))
        return nil, err
    }
    defer rows.Close()

    var logs []models.Log
    for rows.Next() {
        var log models.Log
        err := rows.Scan(&log.ID, &log.UserID, &log.Action, &log.Details, &log.CreatedAt)
        if err != nil {
            utils.LogAction(utils.DB, 1, "error", fmt.Sprintf("Ошибка сканирования логов: %v", err))
            continue
        }
        logs = append(logs, log)
    }
    if err = rows.Err(); err != nil {
        utils.LogAction(utils.DB, 1, "error", fmt.Sprintf("Ошибка обработки логов: %v", err))
        return nil, err
    }
    return logs, nil
}

func searchUserLogs(currentUserID int, userIDQuery, actionQuery, detailsQuery, startDate, endDate string) ([]models.Log, error) {
    var conditions []string
    var args []interface{}

    conditions = append(conditions, "user_id = ?")
    args = append(args, currentUserID)

    if actionQuery != "" {
        conditions = append(conditions, "action LIKE ?")
        args = append(args, "%"+actionQuery+"%")
    }

    if detailsQuery != "" {
        conditions = append(conditions, "details LIKE ?")
        args = append(args, "%"+detailsQuery+"%")
    }

    if startDate != "" && endDate != "" {
        conditions = append(conditions, "created_at BETWEEN ? AND ?")
        args = append(args, startDate, endDate)
    } else {
        if startDate != "" {
            conditions = append(conditions, "created_at >= ?")
            args = append(args, startDate)
        }
        if endDate != "" {
            conditions = append(conditions, "created_at <= ?")
            args = append(args, endDate)
        }
    }

    baseQuery := "SELECT id, user_id, action, details, created_at FROM logs WHERE " + strings.Join(conditions, " AND ")
    rows, err := utils.DB.Query(baseQuery, args...)
    if err != nil {
        utils.LogAction(utils.DB, currentUserID, "error", fmt.Sprintf("Ошибка поиска логов пользователя userID=%d: %v", currentUserID, err))
        return nil, err
    }
    defer rows.Close()

    var logs []models.Log
    for rows.Next() {
        var log models.Log
        err := rows.Scan(&log.ID, &log.UserID, &log.Action, &log.Details, &log.CreatedAt)
        if err != nil {
            utils.LogAction(utils.DB, currentUserID, "error", fmt.Sprintf("Ошибка сканирования логов пользователя userID=%d: %v", currentUserID, err))
            continue
        }
        logs = append(logs, log)
    }
    if err = rows.Err(); err != nil {
        utils.LogAction(utils.DB, currentUserID, "error", fmt.Sprintf("Ошибка обработки логов пользователя userID=%d: %v", currentUserID, err))
        return nil, err
    }
    return logs, nil
}