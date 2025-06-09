package main

import (
	"context"
	"fmt"
	"log"
	"myproject/handlers"
	"net/http"

	"myproject/utils"
)

func main() {
	err := utils.InitDB("root:asd@tcp(IP:3306)/diploma_db?parseTime=true")
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	http.Handle("/css/", http.StripPrefix("/css/", http.FileServer(http.Dir("templates/css"))))
	http.Handle("/js/", http.StripPrefix("/js/", http.FileServer(http.Dir("templates/js"))))

	http.HandleFunc("/login", handlers.LoginHandler)

	http.HandleFunc("/", utils.AuthRequired("")(wrapHandler(handlers.HomeHandler, "view_home")))
	http.HandleFunc("/logout", utils.AuthRequired("")(wrapHandler(handlers.LogoutHandler, "logout")))
	http.HandleFunc("/upload_file", utils.AuthRequired("")(wrapHandler(handlers.UploadFile, "upload_file")))
	http.HandleFunc("/delete_file", utils.AuthRequired("")(wrapHandler(handlers.DeleteFile, "delete_file")))
	http.HandleFunc("/search_files", utils.AuthRequired("")(wrapHandler(handlers.SearchFiles, "search_files")))
	http.HandleFunc("/sign_document", utils.AuthRequired("")(wrapHandler(handlers.SignDocument, "sign_document")))
	http.HandleFunc("/verify_document", utils.AuthRequired("")(wrapHandler(handlers.VerifyDocument, "verify_document")))
	http.HandleFunc("/delete_signed_document", utils.AuthRequired("")(wrapHandler(handlers.DeleteSignedDocument, "delete_signed_document")))
	http.HandleFunc("/search_keys", utils.AuthRequired("")(wrapHandler(handlers.SearchKeys, "search_keys")))
	http.HandleFunc("/download_signed_archive", utils.AuthRequired("")(wrapHandler(handlers.DownloadSignedArchive, "download_signed_archive")))
	http.HandleFunc("/upload_verify_archive", utils.AuthRequired("")(wrapHandler(handlers.UploadVerifyArchive, "upload_verify_archive")))

	http.HandleFunc("/add_user", utils.AuthRequired("admin")(wrapHandler(handlers.AddUser, "add_user")))
	http.HandleFunc("/edit_user", utils.AuthRequired("admin")(wrapHandler(handlers.EditUser, "edit_user")))
	http.HandleFunc("/update_user", utils.AuthRequired("admin")(wrapHandler(handlers.UpdateUser, "update_user")))
	http.HandleFunc("/delete_user", utils.AuthRequired("admin")(wrapHandler(handlers.DeleteUser, "delete_user")))
	http.HandleFunc("/search_users", utils.AuthRequired("admin")(wrapHandler(handlers.SearchUsers, "search_users")))
	http.HandleFunc("/generate_key", utils.AuthRequired("admin")(wrapHandler(handlers.GenerateKey, "generate_key")))
	http.HandleFunc("/delete_key", utils.AuthRequired("admin")(wrapHandler(handlers.DeleteKey, "delete_key")))
	http.HandleFunc("/view_certificate", utils.AuthRequired("admin")(wrapHandler(handlers.ViewCertificate, "view_certificate")))
	http.HandleFunc("/logs", utils.AuthRequired("admin")(wrapHandler(handlers.LogsHandler, "view_logs")))

	http.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})

	log.Println("Server started at :8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}

func wrapHandler(handler http.HandlerFunc, action string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID, ok := r.Context().Value("userID").(int)
		if !ok || userID == 0 {
			userID = -1
			ctx := context.WithValue(r.Context(), "role", "guest")
			r = r.WithContext(ctx)
			utils.LogAction(utils.DB, userID, action+"_attempt", fmt.Sprintf("Неавторизованная попытка: %s", action))
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		utils.LogAction(utils.DB, userID, action+"_attempt", fmt.Sprintf("Action: %s", action))
		handler(w, r)
		utils.LogAction(utils.DB, userID, action+"_success", fmt.Sprintf("Action: %s", action))
	}
}
