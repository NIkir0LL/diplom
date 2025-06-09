package utils

import (
    "context"
    "fmt"
    "net/http"
)

func AuthRequired(role string) func(http.HandlerFunc) http.HandlerFunc {
    return func(next http.HandlerFunc) http.HandlerFunc {
        return func(w http.ResponseWriter, r *http.Request) {
            session, err := Store.Get(r, "auth-session")
            if err != nil {
                LogAction(DB, -1, "error", fmt.Sprintf("Ошибка получения сессии: %v", err))
                http.Redirect(w, r, "/login", http.StatusSeeOther)
                return
            }

            userID, ok1 := session.Values["userID"].(int)
            userRole, ok2 := session.Values["role"].(string)
            if !ok1 || !ok2 || userID == 0 {
                LogAction(DB, -1, "auth_failed", fmt.Sprintf("Неавторизованный доступ к %s", r.URL.Path))
                http.Redirect(w, r, "/login", http.StatusSeeOther)
                return
            }

            if role != "" && userRole != role {
                LogAction(DB, userID, "auth_denied", fmt.Sprintf("Доступ запрещён: требуется роль %s", role))
                http.Error(w, "Доступ запрещён", http.StatusForbidden)
                return
            }

            session.Options.MaxAge = 600
            err = session.Save(r, w)
            if err != nil {
                LogAction(DB, userID, "error", fmt.Sprintf("Ошибка сохранения сессии: %v", err))
                http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
                return
            }

            ctx := context.WithValue(r.Context(), "userID", userID)
            ctx = context.WithValue(ctx, "role", userRole)
            r = r.WithContext(ctx)

            LogAction(DB, userID, "auth_success", fmt.Sprintf("Page: %s", r.URL.Path))

            next.ServeHTTP(w, r)
        }
    }
}