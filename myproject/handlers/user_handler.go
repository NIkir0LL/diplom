package handlers

import (
    "html/template"
    "net/http"
    "myproject/models"
    "myproject/utils"
    "strconv"
)

func AddUser(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodPost {
        username := r.FormValue("username")
        password := r.FormValue("password")
        role := r.FormValue("role")

        _, err := utils.DB.Exec("INSERT INTO users (login, password, role) VALUES (?, ?, ?)", username, password, role)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        http.Redirect(w, r, "/add_user", http.StatusSeeOther)
        return
    }

    users, err := getAllUsers()
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    tmpl, err := template.ParseFiles("templates/add_user.html")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    data := struct {
        Users []models.User
    }{
        Users: users,
    }

    tmpl.Execute(w, data)
}

func EditUser(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodPost {
        userID, err := strconv.Atoi(r.FormValue("user_id"))
        if err != nil {
            http.Error(w, "Invalid user ID", http.StatusBadRequest)
            return
        }

        user, err := getUserByID(userID)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        tmpl, err := template.ParseFiles("templates/edit_user.html")
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        data := struct {
            User models.User
        }{
            User: user,
        }

        tmpl.Execute(w, data)
    }
}

func UpdateUser(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodPost {
        userID, err := strconv.Atoi(r.FormValue("user_id"))
        if err != nil {
            http.Error(w, "Invalid user ID", http.StatusBadRequest)
            return
        }

        username := r.FormValue("username")
        role := r.FormValue("role")

        _, err = utils.DB.Exec("UPDATE users SET login = ?, role = ? WHERE id = ?", username, role, userID)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        http.Redirect(w, r, "/add_user", http.StatusSeeOther)
        return
    }
}

func DeleteUser(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodPost {
        userID, err := strconv.Atoi(r.FormValue("user_id"))
        if err != nil {
            http.Error(w, "Invalid user ID", http.StatusBadRequest)
            return
        }

        _, err = utils.DB.Exec("DELETE FROM users WHERE id = ?", userID)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        http.Redirect(w, r, "/add_user", http.StatusSeeOther)
        return
    }
}

func getAllUsers() ([]models.User, error) {
    rows, err := utils.DB.Query("SELECT id, login, role FROM users")
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var users []models.User
    for rows.Next() {
        var user models.User
        err := rows.Scan(&user.ID, &user.Login, &user.Role)
        if err != nil {
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
        return user, err
    }
    return user, nil
}
