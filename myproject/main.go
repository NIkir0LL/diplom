package main

import (
    "log"
    "net/http"
    "myproject/handlers"
    "myproject/utils"
)

func main() {
    err := utils.InitDB("root:asd@tcp(localhost:3306)/diploma_db")
    if err != nil {
        log.Fatalf("Failed to initialize database: %v", err)
    }

    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        http.ServeFile(w, r, "templates/index.html")
    })
    http.HandleFunc("/add_user", handlers.AddUser)
    http.HandleFunc("/edit_user", handlers.EditUser)
    http.HandleFunc("/update_user", handlers.UpdateUser)
    http.HandleFunc("/delete_user", handlers.DeleteUser)
    http.HandleFunc("/upload_file", handlers.UploadFile)
    http.HandleFunc("/delete_file", handlers.DeleteFile)
    http.HandleFunc("/generate_key", handlers.GenerateKey)
    http.HandleFunc("/delete_key", handlers.DeleteKey)
    http.HandleFunc("/sign", handlers.SignDocument)
    http.HandleFunc("/get_user_keys", handlers.GetUserKeys)
    http.HandleFunc("/verify_document", handlers.VerifyDocument)
    http.HandleFunc("/delete_signed_document", handlers.DeleteSignedDocument)

    log.Println("Server started at :8083")
    log.Fatal(http.ListenAndServe(":8083", nil))
}
