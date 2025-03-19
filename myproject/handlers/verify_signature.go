package handlers

import (
    "crypto"
    "crypto/rsa"
    "crypto/sha256"
    "crypto/x509"
    "encoding/pem"
    "html/template"
    "log"
    "net/http"
    "myproject/models"
    "myproject/utils"
    "os"
    "path/filepath"
    "strconv"
)

// VerifyDocument обрабатывает запросы на проверку подписанного документа.
func VerifyDocument(w http.ResponseWriter, r *http.Request) {
    log.Println("VerifyDocument handler called")

    if r.Method == http.MethodPost {
        log.Println("POST request received")

        // Получение и проверка file_id из формы
        fileID, err := strconv.Atoi(r.FormValue("file_id"))
        if err != nil {
            log.Printf("Invalid file ID: %v", err)
            http.Error(w, "Invalid file ID", http.StatusBadRequest)
            return
        }
        log.Printf("File ID: %d", fileID)

        // Получение и проверка key_id из формы
        keyID, err := strconv.Atoi(r.FormValue("key_id"))
        if err != nil {
            log.Printf("Invalid key ID: %v", err)
            http.Error(w, "Invalid key ID", http.StatusBadRequest)
            return
        }
        log.Printf("Key ID: %d", keyID)

        // Получение подписанного документа из базы данных
        signedDoc, err := getSignedDocument(fileID, keyID)
        if err != nil {
            log.Printf("Signed document not found: %v", err)
            http.Error(w, "Signed document not found", http.StatusNotFound)
            return
        }
        log.Printf("Signed document retrieved: %+v", signedDoc)

        // Получение информации о ключе из базы данных
        key, err := getKey(signedDoc.KeyID)
        if err != nil {
            log.Printf("Key not found: %v", err)
            http.Error(w, "Key not found", http.StatusNotFound)
            return
        }
        log.Printf("Key retrieved: %+v", key)

        // Формирование полного пути к публичному ключу
        publicKeyPath := filepath.Join("keys", strconv.Itoa(key.UserID)+"_"+key.Bank, "public.pem")
        log.Printf("Full public key path: %s", publicKeyPath)

        // Чтение подписанного файла
        signedFileData, err := os.ReadFile(signedDoc.SignedFilePath)
        if err != nil {
            log.Printf("Error reading signed file: %v", err)
            http.Error(w, "Error reading signed file", http.StatusInternalServerError)
            return
        }
        log.Println("Signed file read successfully")

        // Чтение подписи
        signatureData, err := os.ReadFile(signedDoc.SignaturePath)
        if err != nil {
            log.Printf("Error reading signature file: %v", err)
            http.Error(w, "Error reading signature file", http.StatusInternalServerError)
            return
        }
        log.Println("Signature file read successfully")

        // Чтение публичного ключа
        publicKeyPEM, err := os.ReadFile(publicKeyPath)
        if err != nil {
            log.Printf("Error reading public key: %v", err)
            http.Error(w, "Error reading public key", http.StatusInternalServerError)
            return
        }
        publicKeyBlock, _ := pem.Decode(publicKeyPEM)
        if publicKeyBlock == nil {
            log.Println("Error decoding public key PEM block")
            http.Error(w, "Error decoding public key PEM block", http.StatusInternalServerError)
            return
        }
        publicKey, err := x509.ParsePKCS1PublicKey(publicKeyBlock.Bytes)
        if err != nil {
            log.Printf("Error parsing public key: %v", err)
            http.Error(w, "Error parsing public key", http.StatusInternalServerError)
            return
        }
        log.Println("Public key read successfully")

        // Проверка подписи
        hashed := sha256.Sum256(signedFileData)
        err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signatureData)
        if err != nil {
            log.Println("Signature verification failed")
            renderTemplate(w, "Проверка подписи не прошла. Подпись недействительна.")
            return
        }
        log.Println("Signature verification successful")
        renderTemplate(w, "Проверка подписи прошла успешно.")
    } else {
        log.Println("GET request received")
        renderTemplate(w, "")
    }
}

// DeleteSignedDocument обрабатывает запросы на удаление подписанного документа.
func DeleteSignedDocument(w http.ResponseWriter, r *http.Request) {
    log.Println("DeleteSignedDocument handler called")

    if r.Method == http.MethodPost {
        log.Println("POST request received")

        // Получение и проверка signed_doc_id из формы
        signedDocID, err := strconv.Atoi(r.FormValue("signed_doc_id"))
        if err != nil {
            log.Printf("Invalid signed document ID: %v", err)
            http.Error(w, "Invalid signed document ID", http.StatusBadRequest)
            return
        }
        log.Printf("Signed document ID: %d", signedDocID)

        // Получение информации о подписанном документе из базы данных
        signedDoc, err := getSignedDocumentByID(signedDocID)
        if err != nil {
            log.Printf("Signed document not found: %v", err)
            http.Error(w, "Signed document not found", http.StatusNotFound)
            return
        }
        log.Printf("Signed document retrieved: %+v", signedDoc)

        // Удаление файлов
        err = os.Remove(signedDoc.SignedFilePath)
        if err != nil {
            log.Printf("Error deleting signed file: %v", err)
            http.Error(w, "Error deleting signed file", http.StatusInternalServerError)
            return
        }
        log.Println("Signed file deleted successfully")

        err = os.Remove(signedDoc.SignaturePath)
        if err != nil {
            log.Printf("Error deleting signature file: %v", err)
            http.Error(w, "Error deleting signature file", http.StatusInternalServerError)
            return
        }
        log.Println("Signature file deleted successfully")

        // Удаление записи из базы данных
        _, err = utils.DB.Exec("DELETE FROM signed_documents WHERE id=?", signedDocID)
        if err != nil {
            log.Printf("Error deleting signed document from database: %v", err)
            http.Error(w, "Error deleting signed document from database", http.StatusInternalServerError)
            return
        }
        log.Println("Signed document deleted from database successfully")
        renderTemplate(w, "Документ успешно удален.")
    }
}

// getSignedDocument получает информацию о подписанном документе из базы данных.
func getSignedDocument(fileID, keyID int) (models.SignedDocument, error) {
    var signedDoc models.SignedDocument
    err := utils.DB.QueryRow("SELECT signed_file_path, signature_path, key_id FROM signed_documents WHERE file_id=? AND key_id=?", fileID, keyID).Scan(&signedDoc.SignedFilePath, &signedDoc.SignaturePath, &signedDoc.KeyID)
    return signedDoc, err
}

// getKey получает информацию о ключе из базы данных.
func getKey(keyID int) (models.Key, error) {
    var key models.Key
    err := utils.DB.QueryRow("SELECT user_id, bank, public_key_path FROM signatures WHERE id=?", keyID).Scan(&key.UserID, &key.Bank, &key.PublicKeyPath)
    return key, err
}

// getSignedDocumentByID получает информацию о подписанном документе по его ID.
func getSignedDocumentByID(signedDocID int) (models.SignedDocument, error) {
    var signedDoc models.SignedDocument
    err := utils.DB.QueryRow("SELECT signed_file_path, signature_path FROM signed_documents WHERE id=?", signedDocID).Scan(&signedDoc.SignedFilePath, &signedDoc.SignaturePath)
    return signedDoc, err
}

// renderTemplate рендерит шаблон с данными.
func renderTemplate(w http.ResponseWriter, alert string) {
    files, err := getFiles()
    if err != nil {
        log.Printf("Error retrieving files: %v", err)
        http.Error(w, "Error retrieving files", http.StatusInternalServerError)
        return
    }

    keys, err := getKeys()
    if err != nil {
        log.Printf("Error retrieving keys: %v", err)
        http.Error(w, "Error retrieving keys", http.StatusInternalServerError)
        return
    }

    signedDocuments, err := getSignedDocuments()
    if err != nil {
        log.Printf("Error retrieving signed documents: %v", err)
        http.Error(w, "Error retrieving signed documents", http.StatusInternalServerError)
        return
    }

    data := struct {
        Files          []models.File
        Keys           []models.Key
        SignedDocuments []models.SignedDocument
        Alert          string
    }{
        Files:          files,
        Keys:           keys,
        SignedDocuments: signedDocuments,
        Alert:          alert,
    }

    tmpl, err := template.ParseFiles("templates/verify_document.html")
    if err != nil {
        log.Printf("Error parsing template: %v", err)
        http.Error(w, "Error parsing template", http.StatusInternalServerError)
        return
    }
    log.Println("Rendering template")
    tmpl.Execute(w, data)
}

// getFiles получает список файлов из базы данных.
func getFiles() ([]models.File, error) {
    var files []models.File
    rows, err := utils.DB.Query("SELECT id, filename FROM files")
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    for rows.Next() {
        var file models.File
        err := rows.Scan(&file.ID, &file.Filename)
        if err != nil {
            return nil, err
        }
        files = append(files, file)
    }
    return files, nil
}

// getKeys получает список ключей из базы данных.
func getKeys() ([]models.Key, error) {
    var keys []models.Key
    rows, err := utils.DB.Query("SELECT id, bank FROM signatures")
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    for rows.Next() {
        var key models.Key
        err := rows.Scan(&key.ID, &key.Bank)
        if err != nil {
            return nil, err
        }
        keys = append(keys, key)
    }
    return keys, nil
}

// getSignedDocuments получает список подписанных документов из базы данных.
func getSignedDocuments() ([]models.SignedDocument, error) {
    var signedDocuments []models.SignedDocument
    rows, err := utils.DB.Query("SELECT id, file_id, key_id, signed_file_path, signature_path, public_key_path, certificate_path FROM signed_documents")
    if err != nil {
        return nil, err
    }
    defer rows.Close()
    for rows.Next() {
        var signedDoc models.SignedDocument
        err := rows.Scan(&signedDoc.ID, &signedDoc.FileID, &signedDoc.KeyID, &signedDoc.SignedFilePath, &signedDoc.SignaturePath, &signedDoc.PublicKeyPath, &signedDoc.CertificatePath)
        if err != nil {
            return nil, err
        }
        signedDocuments = append(signedDocuments, signedDoc)
    }
    return signedDocuments, nil
}
