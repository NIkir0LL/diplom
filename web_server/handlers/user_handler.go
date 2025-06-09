package handlers

import (
    "fmt"
    "html/template"
    "log"
    "myproject/models"
    "myproject/utils"
    "net/http"
    "strconv"
    "golang.org/x/crypto/bcrypt"
)

var store = utils.Store

// Функция для хеширования пароля
func hashPassword(password string) (string, error) {
    bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    return string(bytes), err
}

// Функция для проверки пароля
func checkPasswordHash(password, hash string) bool {
    err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
    return err == nil
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
    session, err := store.Get(r, "auth-session")
    if err != nil {
        utils.LogAction(utils.DB, -1, "error", fmt.Sprintf("Ошибка получения auth-сессии: %v", err))
        http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
        return
    }
    alertSession, err := store.Get(r, "alert-session")
    if err != nil {
        utils.LogAction(utils.DB, -1, "error", fmt.Sprintf("Ошибка получения alert-сессии: %v", err))
        http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
        return
    }

    // Проверяем, авторизован ли пользователь
    if userID, ok := session.Values["userID"].(int); ok && userID != 0 {
        utils.LogAction(utils.DB, userID, "redirect_already_logged_in", "Уже авторизован, перенаправление на главную")
        http.Redirect(w, r, "/", http.StatusSeeOther)
        return
    }

    if r.Method == http.MethodPost {
        utils.LogAction(utils.DB, -1, "login_attempt", fmt.Sprintf("Попытка входа с IP: %s", r.RemoteAddr))

        username := r.FormValue("username")
        password := r.FormValue("password")

        user, err := getUserByUsername(username)
        if err != nil || !checkPasswordHash(password, user.Password) {
            utils.LogAction(utils.DB, -1, "login_failed", "Неверный логин или пароль")
            alertSession.Values["alert"] = "Неверный логин или пароль."
            alertSession.Values["alertType"] = "danger"
            alertSession.Save(r, w)
            http.Redirect(w, r, "/login", http.StatusSeeOther)
            return
        }

        session.Values = make(map[interface{}]interface{})
        session.Values["userID"] = user.ID
        session.Values["role"] = user.Role
        session.Options.MaxAge = 600

        err = session.Save(r, w)
        if err != nil {
            utils.LogAction(utils.DB, user.ID, "error", fmt.Sprintf("Ошибка сохранения сессии: %v", err))
            alertSession.Values["alert"] = "Ошибка сервера при входе."
            alertSession.Values["alertType"] = "danger"
            alertSession.Save(r, w)
            http.Redirect(w, r, "/login", http.StatusSeeOther)
            return
        }

        utils.LogAction(utils.DB, user.ID, "login_success", fmt.Sprintf("Вход пользователя: %s", username))
        log.Printf("Успешный вход для userID: %d, role: %s, session: %+v", user.ID, user.Role, session.Values)
        http.Redirect(w, r, "/", http.StatusSeeOther)
        return
    }

    alert, hasAlert := alertSession.Values["alert"].(string)
    alertType, _ := alertSession.Values["alertType"].(string)
    if hasAlert {
        utils.LogAction(utils.DB, -1, "display_alert", fmt.Sprintf("Алерт: %s", alert))
        delete(alertSession.Values, "alert")
        delete(alertSession.Values, "alertType")
        alertSession.Save(r, w)
    }

    tmpl, err := template.ParseFiles("templates/login.html")
    if err != nil {
        utils.LogAction(utils.DB, -1, "error", fmt.Sprintf("Ошибка парсинга шаблона login.html: %v", err))
        http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
        return
    }

    data := struct {
        Alert     string
        AlertType string
        HasAlert  bool
    }{
        Alert:     alert,
        AlertType: alertType,
        HasAlert:  hasAlert,
    }

    err = tmpl.Execute(w, data)
    if err != nil {
        utils.LogAction(utils.DB, -1, "error", fmt.Sprintf("Ошибка выполнения шаблона login.html: %v", err))
        http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
        return
    }

    utils.LogAction(utils.DB, -1, "render_login_success", "Рендеринг страницы логина")
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, "auth-session")
    userID, ok := session.Values["userID"].(int)
    if !ok {
        userID = -1
    }

    utils.LogAction(utils.DB, userID, "logout_attempt", "Попытка выхода")

    session.Values["userID"] = nil
    session.Values["role"] = nil
    session.Options.MaxAge = -1
    err := session.Save(r, w)
    if err != nil {
        utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка очистки сессии: %v", err))
    }

    utils.LogAction(utils.DB, userID, "logout_success", "Выход из системы")
    http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func HomeHandler(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, "alert-session")
    userID := r.Context().Value("userID").(int)
    role := r.Context().Value("role").(string)

    utils.LogAction(utils.DB, userID, "view_home_attempt", "Попытка просмотра главной страницы")

    alert, hasAlert := session.Values["alert"].(string)
    alertType, _ := session.Values["alertType"].(string)
    if hasAlert {
        utils.LogAction(utils.DB, userID, "display_alert", fmt.Sprintf("Алерт: %s", alert))
        delete(session.Values, "alert")
        delete(session.Values, "alertType")
        session.Save(r, w)
    }

    var tmpl *template.Template
    var err error
    if role == "admin" {
        tmpl, err = template.ParseFiles("templates/admin_dashboard.html")
    } else {
        tmpl, err = template.ParseFiles("templates/user_dashboard.html")
    }
    if err != nil {
        log.Printf("Ошибка парсинга шаблона: %v", err)
        utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка парсинга шаблона: %v", err))
        http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
        return
    }

    data := struct {
        Alert     string
        AlertType string
        HasAlert  bool
    }{
        Alert:     alert,
        AlertType: alertType,
        HasAlert:  hasAlert,
    }

    err = tmpl.Execute(w, data)
    if err != nil {
        log.Printf("Ошибка выполнения шаблона: %v", err)
        utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка выполнения шаблона: %v", err))
        http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
        return
    }

    utils.LogAction(utils.DB, userID, "view_home_success", "Рендеринг главной страницы")
}

func AddUser(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, "alert-session")
    userID := r.Context().Value("userID").(int)

    utils.LogAction(utils.DB, userID, "add_user_attempt", "Попытка добавления пользователя")

    if r.Method == http.MethodPost {
        username := r.FormValue("username")
        password := r.FormValue("password")
        role := r.FormValue("role")

        if username == "" || password == "" || role == "" {
            utils.LogAction(utils.DB, userID, "error", "Все поля должны быть заполнены")
            session.Values["alert"] = "Все поля должны быть заполнены."
            session.Values["alertType"] = "danger"
            session.Save(r, w)
            http.Redirect(w, r, "/add_user", http.StatusSeeOther)
            return
        }

        hashedPassword, err := hashPassword(password)
        if err != nil {
            log.Printf("Ошибка хеширования пароля: %v", err)
            utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка хеширования пароля: %v", err))
            session.Values["alert"] = "Ошибка сервера при добавлении пользователя."
            session.Values["alertType"] = "danger"
            session.Save(r, w)
            http.Redirect(w, r, "/add_user", http.StatusSeeOther)
            return
        }

        _, err = utils.DB.Exec("INSERT INTO users (login, password, role) VALUES (?, ?, ?)", username, hashedPassword, role)
        if err != nil {
            log.Printf("Ошибка добавления пользователя: %v", err)
            utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка добавления пользователя: %v", err))
            session.Values["alert"] = "Ошибка сервера при добавлении пользователя."
            session.Values["alertType"] = "danger"
            session.Save(r, w)
            http.Redirect(w, r, "/add_user", http.StatusSeeOther)
            return
        }

        utils.LogAction(utils.DB, userID, "add_user_success", fmt.Sprintf("Добавлен пользователь: %s", username))
        session.Values["alert"] = "Пользователь успешно добавлен."
        session.Values["alertType"] = "success"
        session.Save(r, w)
        http.Redirect(w, r, "/add_user", http.StatusSeeOther)
        return
    }

    users, err := getAllUsers()
    if err != nil {
        log.Printf("Ошибка получения пользователей: %v", err)
        utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка получения пользователей: %v", err))
        http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
        return
    }

    alert, hasAlert := session.Values["alert"].(string)
    alertType, _ := session.Values["alertType"].(string)
    if hasAlert {
        utils.LogAction(utils.DB, userID, "display_alert", fmt.Sprintf("Алерт: %s", alert))
        delete(session.Values, "alert")
        delete(session.Values, "alertType")
        session.Save(r, w)
    }

    tmpl, err := template.ParseFiles("templates/add_user.html")
    if err != nil {
        log.Printf("Ошибка парсинга шаблона: %v", err)
        utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка парсинга шаблона: %v", err))
        http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
        return
    }

    data := struct {
        Users     []models.User
        Alert     string
        AlertType string
        HasAlert  bool
    }{
        Users:     users,
        Alert:     alert,
        AlertType: alertType,
        HasAlert:  hasAlert,
    }

    err = tmpl.Execute(w, data)
    if err != nil {
        log.Printf("Ошибка выполнения шаблона: %v", err)
        utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка выполнения шаблона: %v", err))
        http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
        return
    }

    utils.LogAction(utils.DB, userID, "render_add_user_success", "Рендеринг страницы добавления пользователя")
}

func EditUser(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, "alert-session")
    userID := r.Context().Value("userID").(int)

    utils.LogAction(utils.DB, userID, "edit_user_attempt", "Попытка редактирования пользователя")

    userIDStr := r.URL.Query().Get("id")
    if r.Method == http.MethodPost {
        userIDStr = r.FormValue("user_id")
    }

    if userIDStr == "" {
        utils.LogAction(utils.DB, userID, "error", "ID пользователя не указан")
        session.Values["alert"] = "ID пользователя не указан."
        session.Values["alertType"] = "danger"
        session.Save(r, w)
        http.Redirect(w, r, "/add_user", http.StatusSeeOther)
        return
    }

    targetUserID, err := strconv.Atoi(userIDStr)
    if err != nil {
        log.Printf("Неверный ID пользователя: %v", err)
        utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Неверный ID пользователя: %v", err))
        session.Values["alert"] = "Неверный ID пользователя."
        session.Values["alertType"] = "danger"
        session.Save(r, w)
        http.Redirect(w, r, "/add_user", http.StatusSeeOther)
        return
    }

    user, err := getUserByID(targetUserID)
    if err != nil {
        log.Printf("Пользователь не найден: %v", err)
        utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Пользователь не найден: %v", err))
        session.Values["alert"] = "Пользователь не найден."
        session.Values["alertType"] = "danger"
        session.Save(r, w)
        http.Redirect(w, r, "/add_user", http.StatusSeeOther)
        return
    }

    alert, hasAlert := session.Values["alert"].(string)
    alertType, _ := session.Values["alertType"].(string)
    if hasAlert {
        utils.LogAction(utils.DB, userID, "display_alert", fmt.Sprintf("Алерт: %s", alert))
        delete(session.Values, "alert")
        delete(session.Values, "alertType")
        session.Save(r, w)
    }

    tmpl, err := template.ParseFiles("templates/edit_user.html")
    if err != nil {
        log.Printf("Ошибка парсинга шаблона: %v", err)
        utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка парсинга шаблона: %v", err))
        http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
        return
    }

    data := struct {
        User      models.User
        Alert     string
        AlertType string
        HasAlert  bool
    }{
        User:      user,
        Alert:     alert,
        AlertType: alertType,
        HasAlert:  hasAlert,
    }

    err = tmpl.Execute(w, data)
    if err != nil {
        log.Printf("Ошибка выполнения шаблона: %v", err)
        utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка выполнения шаблона: %v", err))
        http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
        return
    }

    utils.LogAction(utils.DB, userID, "edit_user_success", fmt.Sprintf("Рендеринг страницы редактирования пользователя: %d", targetUserID))
}

func UpdateUser(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, "alert-session")
    adminID := r.Context().Value("userID").(int)

    utils.LogAction(utils.DB, adminID, "update_user_attempt", "Попытка обновления пользователя")

    if r.Method == http.MethodPost {
        userID, err := strconv.Atoi(r.FormValue("user_id"))
        if err != nil {
            log.Printf("Неверный ID пользователя: %v", err)
            utils.LogAction(utils.DB, adminID, "error", fmt.Sprintf("Неверный ID пользователя: %v", err))
            session.Values["alert"] = "Неверный ID пользователя."
            session.Values["alertType"] = "danger"
            session.Save(r, w)
            http.Redirect(w, r, "/add_user", http.StatusSeeOther)
            return
        }

        username := r.FormValue("username")
        role := r.FormValue("role")

        if username == "" || role == "" {
            utils.LogAction(utils.DB, adminID, "error", "Все поля должны быть заполнены")
            session.Values["alert"] = "Все поля должны быть заполнены."
            session.Values["alertType"] = "danger"
            session.Save(r, w)
            http.Redirect(w, r, "/edit_user?id="+strconv.Itoa(userID), http.StatusSeeOther)
            return
        }

        currentUser, err := getUserByID(userID)
        if err != nil {
            log.Printf("Пользователь не найден: %v", err)
            utils.LogAction(utils.DB, adminID, "error", fmt.Sprintf("Пользователь не найден: %v", err))
            session.Values["alert"] = "Пользователь не найден."
            session.Values["alertType"] = "danger"
            session.Save(r, w)
            http.Redirect(w, r, "/edit_user?id="+strconv.Itoa(userID), http.StatusSeeOther)
            return
        }

        var logDetails []string
        if currentUser.Login != username {
            logDetails = append(logDetails, fmt.Sprintf("login: %s->%s", currentUser.Login, username))
        }
        if currentUser.Role != role {
            logDetails = append(logDetails, fmt.Sprintf("role: %s->%s", currentUser.Role, role))
        }
        logMessage := fmt.Sprintf("Обновлён пользователь: %d", userID)
        if len(logDetails) > 0 {
            logMessage += ", " + utils.Join(logDetails, ", ")
        }

        _, err = utils.DB.Exec("UPDATE users SET login = ?, role = ? WHERE id = ?", username, role, userID)
        if err != nil {
            log.Printf("Ошибка обновления пользователя: %v", err)
            utils.LogAction(utils.DB, adminID, "error", fmt.Sprintf("Ошибка обновления пользователя: %v", err))
            session.Values["alert"] = "Ошибка сервера при обновлении пользователя."
            session.Values["alertType"] = "danger"
            session.Save(r, w)
            http.Redirect(w, r, "/edit_user?id="+strconv.Itoa(userID), http.StatusSeeOther)
            return
        }

        utils.LogAction(utils.DB, adminID, "update_user_success", logMessage)
        session.Values["alert"] = "Пользователь успешно обновлён."
        session.Values["alertType"] = "success"
        session.Save(r, w)
        http.Redirect(w, r, "/add_user", http.StatusSeeOther)
        return
    }
}

func DeleteUser(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, "alert-session")
    adminID := r.Context().Value("userID").(int)

    utils.LogAction(utils.DB, adminID, "delete_user_attempt", "Попытка удаления пользователя")

    if r.Method == http.MethodPost {
        userID, err := strconv.Atoi(r.FormValue("user_id"))
        if err != nil {
            log.Printf("Неверный ID пользователя: %v", err)
            utils.LogAction(utils.DB, adminID, "error", fmt.Sprintf("Неверный ID пользователя: %v", err))
            session.Values["alert"] = "Неверный ID пользователя."
            session.Values["alertType"] = "danger"
            session.Save(r, w)
            http.Redirect(w, r, "/add_user", http.StatusSeeOther)
            return
        }

        var count int
        err = utils.DB.QueryRow("SELECT COUNT(*) FROM signatures WHERE user_id = ?", userID).Scan(&count)
        if err != nil {
            log.Printf("Ошибка проверки ключей: %v", err)
            utils.LogAction(utils.DB, adminID, "error", fmt.Sprintf("Ошибка проверки ключей: %v", err))
            session.Values["alert"] = "Ошибка сервера при проверке данных."
            session.Values["alertType"] = "danger"
            session.Save(r, w)
            http.Redirect(w, r, "/add_user", http.StatusSeeOther)
            return
        }
        if count > 0 {
            utils.LogAction(utils.DB, adminID, "error", fmt.Sprintf("Нельзя удалить пользователя: %d ключей", count))
            session.Values["alert"] = "Нельзя удалить пользователя, так как у него есть ключи."
            session.Values["alertType"] = "danger"
            session.Save(r, w)
            http.Redirect(w, r, "/add_user", http.StatusSeeOther)
            return
        }

        _, err = utils.DB.Exec("DELETE FROM users WHERE id = ?", userID)
        if err != nil {
            log.Printf("Ошибка удаления пользователя: %v", err)
            utils.LogAction(utils.DB, adminID, "error", fmt.Sprintf("Ошибка удаления пользователя: %v", err))
            session.Values["alert"] = "Ошибка сервера при удалении пользователя."
            session.Values["alertType"] = "danger"
            session.Save(r, w)
            http.Redirect(w, r, "/add_user", http.StatusSeeOther)
            return
        }

        utils.LogAction(utils.DB, adminID, "delete_user_success", fmt.Sprintf("Удалён пользователь: %d", userID))
        session.Values["alert"] = "Пользователь успешно удалён."
        session.Values["alertType"] = "success"
        session.Save(r, w)
        http.Redirect(w, r, "/add_user", http.StatusSeeOther)
        return
    }
}

func SearchUsers(w http.ResponseWriter, r *http.Request) {
    session, _ := store.Get(r, "alert-session")
    userID := r.Context().Value("userID").(int)

    utils.LogAction(utils.DB, userID, "search_users_attempt", "Попытка поиска пользователей")

    query := r.URL.Query().Get("query")

    var users []models.User
    var err error

    if query == "" {
        users, err = getAllUsers()
        if err == nil {
            utils.LogAction(utils.DB, userID, "search_users_success", fmt.Sprintf("Получено пользователей: %d", len(users)))
        }
    } else {
        users, err = searchUsers(query)
        if err == nil && len(users) == 0 {
            utils.LogAction(utils.DB, userID, "search_users_empty", fmt.Sprintf("По запросу '%s' ничего не найдено", query))
            session.Values["alert"] = "Пользователи по запросу \"" + query + "\" не найдены."
            session.Values["alertType"] = "danger"
        } else if err == nil {
            utils.LogAction(utils.DB, userID, "search_users_success", fmt.Sprintf("Найдено пользователей: %d", len(users)))
        }
    }

    if err != nil {
        log.Printf("Ошибка поиска пользователей: %v", err)
        utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка поиска пользователей: %v", err))
        http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
        return
    }

    alert, hasAlert := session.Values["alert"].(string)
    alertType, _ := session.Values["alertType"].(string)
    if hasAlert {
        utils.LogAction(utils.DB, userID, "display_alert", fmt.Sprintf("Алерт: %s", alert))
        delete(session.Values, "alert")
        delete(session.Values, "alertType")
        session.Save(r, w)
    }

    tmpl, err := template.ParseFiles("templates/add_user.html")
    if err != nil {
        log.Printf("Ошибка парсинга шаблона: %v", err)
        utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка парсинга шаблона: %v", err))
        http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
        return
    }

    data := struct {
        Users     []models.User
        Alert     string
        AlertType string
        HasAlert  bool
    }{
        Users:     users,
        Alert:     alert,
        AlertType: alertType,
        HasAlert:  hasAlert,
    }

    err = tmpl.Execute(w, data)
    if err != nil {
        log.Printf("Ошибка выполнения шаблона: %v", err)
        utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка выполнения шаблона: %v", err))
        http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
        return
    }

    utils.LogAction(utils.DB, userID, "render_search_users_success", "Рендеринг страницы поиска пользователей")
}

func getAllUsers() ([]models.User, error) {
    rows, err := utils.DB.Query("SELECT id, login, role FROM users")
    if err != nil {
        utils.LogAction(utils.DB, -1, "error", fmt.Sprintf("Ошибка получения пользователей: %v", err))
        return nil, err
    }
    defer rows.Close()

    var users []models.User
    for rows.Next() {
        var user models.User
        err := rows.Scan(&user.ID, &user.Login, &user.Role)
        if err != nil {
            utils.LogAction(utils.DB, -1, "error", fmt.Sprintf("Ошибка сканирования пользователей: %v", err))
            return nil, err
        }
        users = append(users, user)
    }

    return users, nil
}

func getUserByID(userID int) (models.User, error) {
    var user models.User
    err := utils.DB.QueryRow("SELECT id, login, role FROM users WHERE id = ?", userID).Scan(&user.ID, &user.Login, &user.Role)
    if err != nil {
        utils.LogAction(utils.DB, -1, "error", fmt.Sprintf("Ошибка получения пользователя: %v", err))
        return user, err
    }
    return user, nil
}

func getUserByUsername(username string) (models.User, error) {
    var user models.User
    err := utils.DB.QueryRow("SELECT id, login, password, role FROM users WHERE login = ?", username).Scan(&user.ID, &user.Login, &user.Password, &user.Role)
    if err != nil {
        utils.LogAction(utils.DB, -1, "error", fmt.Sprintf("Ошибка получения пользователя: %v", err))
        return user, err
    }
    return user, nil
}

func searchUsers(query string) ([]models.User, error) {
    rows, err := utils.DB.Query("SELECT id, login, role FROM users WHERE login LIKE ? OR role LIKE ?", "%"+query+"%", "%"+query+"%")
    if err != nil {
        utils.LogAction(utils.DB, -1, "error", fmt.Sprintf("Ошибка поиска пользователей: %v", err))
        return nil, err
    }
    defer rows.Close()

    var users []models.User
    for rows.Next() {
        var user models.User
        err := rows.Scan(&user.ID, &user.Login, &user.Role)
        if err != nil {
            utils.LogAction(utils.DB, -1, "error", fmt.Sprintf("Ошибка сканирования пользователей: %v", err))
            return nil, err
        }
        users = append(users, user)
    }

    return users, nil
}