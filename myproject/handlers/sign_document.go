package handlers

import (
    "crypto"
    "crypto/rand"
    "crypto/rsa"
    "crypto/sha256"
    "crypto/x509"
    "encoding/json"
    "encoding/pem"
    "fmt"
    "html/template"
    "io/ioutil"
    "net/http"
    "myproject/models"
    "myproject/utils"
    "os"
    "path/filepath"
    "strconv"
)

func SignDocument(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodPost {
        fileID, _ := strconv.Atoi(r.FormValue("file_id"))
        bankID, _ := strconv.Atoi(r.FormValue("bank_id"))

        // Получение файла из базы данных
        var file models.File
        err := utils.DB.QueryRow("SELECT filename, filepath FROM files WHERE id=?", fileID).Scan(&file.Filename, &file.Filepath)
        if err != nil {
            http.Error(w, "File not found", http.StatusNotFound)
            return
        }

        // Получение ключей из базы данных
        var key models.Key
        err = utils.DB.QueryRow("SELECT user_id, bank, public_key_path, private_key_path, certificate_path FROM signatures WHERE id=?", bankID).Scan(&key.UserID, &key.Bank, &key.PublicKeyPath, &key.PrivateKeyPath, &key.CertificatePath)
        if err != nil {
            http.Error(w, "Key not found", http.StatusNotFound)
            return
        }

        // Чтение файла
        filePath := filepath.Join("uploads", file.Filename)
        fileData, err := ioutil.ReadFile(filePath)
        if err != nil {
            http.Error(w, "Error reading file", http.StatusInternalServerError)
            return
        }

        // Формирование пути к приватному ключу
        keyDir := filepath.Join("keys", strconv.Itoa(key.UserID)+"_"+key.Bank)
        privateKeyPath := filepath.Join(keyDir, "private.pem")

        // Чтение приватного ключа
        privateKeyPEM, err := ioutil.ReadFile(privateKeyPath)
        if err != nil {
            http.Error(w, "Error reading private key", http.StatusInternalServerError)
            return
        }
        privateKeyBlock, _ := pem.Decode(privateKeyPEM)
        if privateKeyBlock == nil {
            http.Error(w, "Error decoding private key PEM block", http.StatusInternalServerError)
            return
        }
        privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
        if err != nil {
            http.Error(w, "Error parsing private key", http.StatusInternalServerError)
            return
        }

        // Подписание файла
        hashed := sha256.Sum256(fileData)
        signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
        if err != nil {
            http.Error(w, "Error signing file", http.StatusInternalServerError)
            return
        }

        // Создание папки для подписанных документов
        signedDir := filepath.Join("signed", strconv.Itoa(key.UserID)+"_"+key.Bank)
        err = os.MkdirAll(signedDir, os.ModePerm)
        if err != nil {
            http.Error(w, "Error creating signed directory", http.StatusInternalServerError)
            return
        }

        // Сохранение подписанного файла
        signedFilePath := filepath.Join(signedDir, fmt.Sprintf("signed_%s", file.Filename))
        err = ioutil.WriteFile(signedFilePath, fileData, 0644)
        if err != nil {
            http.Error(w, "Error writing signed file", http.StatusInternalServerError)
            return
        }

        // Сохранение подписи
        signaturePath := filepath.Join(signedDir, fmt.Sprintf("signature_%s.sig", file.Filename))
        err = ioutil.WriteFile(signaturePath, signature, 0644)
        if err != nil {
            http.Error(w, "Error writing signature file", http.StatusInternalServerError)
            return
        }

        // Сохранение информации о подписанном документе в базу данных
        _, err = utils.DB.Exec("INSERT INTO signed_documents (file_id, key_id, signed_file_path, signature_path, public_key_path, certificate_path) VALUES (?, ?, ?, ?, ?, ?)", fileID, bankID, signedFilePath, signaturePath, key.PublicKeyPath, key.CertificatePath)
        if err != nil {
            http.Error(w, "Error saving signature", http.StatusInternalServerError)
            return
        }

        // Перенаправление на другую страницу после успешного подписания
        http.Redirect(w, r, "/verify_document", http.StatusSeeOther)
    } else {
        // Получение данных для шаблона
        var files []models.File
        rows, err := utils.DB.Query("SELECT id, filename FROM files")
        if err != nil {
            http.Error(w, "Error retrieving files", http.StatusInternalServerError)
            return
        }
        defer rows.Close()
        for rows.Next() {
            var file models.File
            err := rows.Scan(&file.ID, &file.Filename)
            if err != nil {
                http.Error(w, "Error scanning files", http.StatusInternalServerError)
                return
            }
            files = append(files, file)
        }

        var users []models.User
        rows, err = utils.DB.Query("SELECT id, login FROM users")
        if err != nil {
            http.Error(w, "Error retrieving users", http.StatusInternalServerError)
            return
        }
        defer rows.Close()
        for rows.Next() {
            var user models.User
            err := rows.Scan(&user.ID, &user.Login)
            if err != nil {
                http.Error(w, "Error scanning users", http.StatusInternalServerError)
                return
            }
            users = append(users, user)
        }

        data := struct {
            Files []models.File
            Users []models.User
        }{
            Files: files,
            Users: users,
        }

        tmpl := template.Must(template.ParseFiles("templates/sign_document.html"))
        tmpl.Execute(w, data)
    }
}

func GetUserKeys(w http.ResponseWriter, r *http.Request) {
    userID, _ := strconv.Atoi(r.URL.Query().Get("user_id"))

    var keys []models.Key
    rows, err := utils.DB.Query("SELECT id, bank FROM signatures WHERE user_id=?", userID)
    if err != nil {
        http.Error(w, "Error retrieving keys", http.StatusInternalServerError)
        return
    }
    defer rows.Close()
    for rows.Next() {
        var key models.Key
        err := rows.Scan(&key.ID, &key.Bank)
        if err != nil {
            http.Error(w, "Error scanning keys", http.StatusInternalServerError)
            return
        }
        key.UserID = userID
        keys = append(keys, key)
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(keys)
}
