package handlers

import (
    "crypto"
    "crypto/rsa"
    "crypto/sha256"
    "crypto/x509"
    "encoding/pem"
    "fmt"
    "html/template"
    "log"
    "myproject/hsm"
    "myproject/models"
    "myproject/utils"
    "net/http"
    "os"
    "path/filepath"
    "strconv"


)

func VerifyDocument(w http.ResponseWriter, r *http.Request) {
    userID, ok := r.Context().Value("userID").(int)
    if !ok || userID == 0 {
        userID = -1
        utils.LogAction(utils.DB, userID, "error", "Неавторизованный доступ к проверке документа")
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }

    log.Println("VerifyDocument handler called")
    utils.LogAction(utils.DB, userID, "verify_document_attempt", fmt.Sprintf("Вызов обработчика VerifyDocument пользователем userID=%d", userID))

    session, _ := utils.Store.Get(r, "alert-session")
    role := r.Context().Value("role").(string)

    if r.Method == http.MethodGet {
        log.Println("GET request received")
        utils.LogAction(utils.DB, userID, "view_signed_documents_attempt", fmt.Sprintf("Попытка просмотра подписанных документов пользователем userID=%d", userID))

        searchFilename := r.URL.Query().Get("search_filename")
        var signedDocuments []models.SignedDocument

        if searchFilename != "" {
            var err error
            if role == "admin" {
                signedDocuments, err = getSignedDocumentsByFilename(searchFilename)
            } else {
                signedDocuments, err = getUserSignedDocumentsByFilename(userID, searchFilename)
            }
            if err != nil {
                log.Printf("Ошибка поиска документов по названию: %v, search: %s", err, searchFilename)
                utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка поиска документов по названию '%s': %v", searchFilename, err))
                session.Values["alert"] = "Ошибка при поиске документов."
                session.Values["alertType"] = "danger"
                session.Save(r, w)
                http.Redirect(w, r, "/verify_document", http.StatusSeeOther)
                return
            }
            if len(signedDocuments) == 0 {
                utils.LogAction(utils.DB, userID, "search_documents_empty", fmt.Sprintf("Документы с названием '%s' не найдены", searchFilename))
                session.Values["alert"] = fmt.Sprintf("Документы с названием, содержащим \"%s\", не найдены", searchFilename)
                session.Values["alertType"] = "danger"
            } else {
                utils.LogAction(utils.DB, userID, "search_documents_success", fmt.Sprintf("Найдено %d документов с названием '%s'", len(signedDocuments), searchFilename))
            }
        } else {
            var err error
            if role == "admin" {
                signedDocuments, err = getSignedDocuments()
            } else {
                signedDocuments, err = getUserSignedDocuments(userID)
            }
            if err != nil {
                log.Printf("Ошибка получения списка подписанных документов: %v", err)
                utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка получения списка подписанных документов: %v", err))
                session.Values["alert"] = "Ошибка при получении списка документов."
                session.Values["alertType"] = "danger"
                session.Save(r, w)
                http.Redirect(w, r, "/verify_document", http.StatusSeeOther)
                return
            }
            utils.LogAction(utils.DB, userID, "view_documents_success", fmt.Sprintf("Успешно получено %d подписанных документов", len(signedDocuments)))
        }

        renderTemplate(w, r, signedDocuments)
        return
    }

    if r.Method == http.MethodPost {
        log.Println("POST request received")
        utils.LogAction(utils.DB, userID, "verify_document_post_attempt", fmt.Sprintf("Попытка проверки подписи документа пользователем userID=%d", userID))

        fileID, err := strconv.Atoi(r.FormValue("file_id"))
        if err != nil {
            log.Printf("Неверный ID файла: %v", err)
            utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Неверный ID файла: %v", err))
            session.Values["alert"] = "Неверный ID файла."
            session.Values["alertType"] = "danger"
            session.Save(r, w)
            http.Redirect(w, r, "/verify_document", http.StatusSeeOther)
            return
        }
        log.Printf("File ID: %d", fileID)

        keyID, err := strconv.Atoi(r.FormValue("key_id"))
        if err != nil {
            log.Printf("Неверный ID ключа: %v", err)
            utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Неверный ID ключа: %v", err))
            session.Values["alert"] = "Неверный ID ключа."
            session.Values["alertType"] = "danger"
            session.Save(r, w)
            http.Redirect(w, r, "/verify_document", http.StatusSeeOther)
            return
        }
        log.Printf("Key ID: %d", keyID)

        signedDoc, err := getSignedDocument(fileID, keyID)
        if err != nil {
            log.Printf("Подписанный документ не найден: %v, fileID: %d, keyID: %d", err, fileID, keyID)
            utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Подписанный документ не найден, fileID=%d, keyID=%d: %v", fileID, keyID, err))
            session.Values["alert"] = "Подписанный документ не найден."
            session.Values["alertType"] = "danger"
            session.Save(r, w)
            http.Redirect(w, r, "/verify_document", http.StatusSeeOther)
            return
        }
        log.Printf("Подписанный документ получен: %+v", signedDoc)

        signature, err := getSignature(signedDoc.KeyID)
        if err != nil {
            log.Printf("Ключ не найден: %v, keyID: %d", err, keyID)
            utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ключ не найден, keyID=%d: %v", keyID, err))
            session.Values["alert"] = "Ключ не найден."
            session.Values["alertType"] = "danger"
            session.Save(r, w)
            http.Redirect(w, r, "/verify_document", http.StatusSeeOther)
            return
        }
        log.Printf("Ключ получен: %+v", signature)

        if role != "admin" && signature.UserID != userID {
            log.Printf("Попытка проверки чужого документа: userID %d, keyID %d", userID, keyID)
            utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Попытка проверки чужого документа, userID=%d, keyID=%d", userID, keyID))
            session.Values["alert"] = "У вас нет прав для проверки этого документа."
            session.Values["alertType"] = "danger"
            session.Save(r, w)
            http.Redirect(w, r, "/verify_document", http.StatusSeeOther)
            return
        }

        // Формирование пути для HSM
        hsmFilePath := signedDoc.SignedFilePath
        log.Printf("Попытка загрузки подписанного файла из HSM: userID=%s, type=file, path=%s", strconv.Itoa(signature.UserID), hsmFilePath)

        // Загрузка подписанного файла из HSM
        signedData, err := hsm.Retrieve(strconv.Itoa(signature.UserID), "file", hsmFilePath)
        if err != nil {
            log.Printf("Ошибка загрузки подписанного файла из HSM: %v, userID=%d, path=%s", err, signature.UserID, hsmFilePath)
            // Попытка локальной загрузки файла
            localFilePath := filepath.Join("data/users", strconv.Itoa(signature.UserID), "file/files/signed", strconv.Itoa(signature.UserID), filepath.Base(signedDoc.SignedFilePath))
            log.Printf("Попытка локальной загрузки подписанного файла: %s", localFilePath)
            signedData, err = os.ReadFile(localFilePath)
            if err != nil {
                log.Printf("Ошибка локальной загрузки подписанного файла: %v, path=%s", err, localFilePath)
                session.Values["alert"] = fmt.Sprintf("Подписанный файл не найден: %s", signedDoc.Filename)
                session.Values["alertType"] = "danger"
                session.Save(r, w)
                http.Redirect(w, r, "/verify_document", http.StatusSeeOther)
                return
            }
            log.Printf("Подписанный файл успешно загружен локально: userID=%d, path=%s, размер=%d байт", signature.UserID, localFilePath, len(signedData))
        } else {
            log.Printf("Подписанный файл успешно загружен из HSM: userID=%d, path=%s, размер=%d байт", signature.UserID, hsmFilePath, len(signedData))
        }

        // Загрузка подписи из HSM
        hsmSignaturePath := signedDoc.SignaturePath
        log.Printf("Попытка загрузки подписи из HSM: userID=%s, type=signature, path=%s", strconv.Itoa(signature.UserID), hsmSignaturePath)

        signatureData, err := hsm.Retrieve(strconv.Itoa(signature.UserID), "signature", hsmSignaturePath)
        if err != nil {
            log.Printf("Ошибка загрузки подписи из HSM: %v, userID=%d, path=%s", err, signature.UserID, hsmSignaturePath)
            // Попытка локальной загрузки подписи
            localSignaturePath := filepath.Join("data/users", strconv.Itoa(signature.UserID), "signature/signatures", strconv.Itoa(signature.UserID), filepath.Base(signedDoc.SignaturePath))
            log.Printf("Попытка локальной загрузки подписи: %s", localSignaturePath)
            signatureData, err = os.ReadFile(localSignaturePath)
            if err != nil {
                log.Printf("Ошибка локальной загрузки подписи: %v, path=%s", err, localSignaturePath)
                session.Values["alert"] = fmt.Sprintf("Файл подписи не найден: %s", filepath.Base(signedDoc.SignaturePath))
                session.Values["alertType"] = "danger"
                session.Save(r, w)
                http.Redirect(w, r, "/verify_document", http.StatusSeeOther)
                return
            }
            log.Printf("Подпись успешно загружена локально: userID=%d, path=%s, размер=%d байт", signature.UserID, localSignaturePath, len(signatureData))
        } else {
            log.Printf("Подпись успешно загружена из HSM: userID=%d, path=%s, размер=%d байт", signature.UserID, hsmSignaturePath, len(signatureData))
        }

        // Загрузка публичного ключа из HSM
        hsmPublicKeyPath := signedDoc.PublicKeyPath
        log.Printf("Попытка загрузки публичного ключа из HSM: userID=%s, type=key, path=%s", strconv.Itoa(signature.UserID), hsmPublicKeyPath)

        publicKeyPEM, err := hsm.Retrieve(strconv.Itoa(signature.UserID), "key", hsmPublicKeyPath)
        if err != nil {
            log.Printf("Ошибка загрузки публичного ключа из HSM: %v, userID=%d, path=%s", err, signature.UserID, hsmPublicKeyPath)
            // Попытка локальной загрузки публичного ключа
            localPublicKeyPath := filepath.Join("data/users", strconv.Itoa(signature.UserID), "keys", "qwerqwer", "public.pem")
            log.Printf("Попытка локальной загрузки публичного ключа: %s", localPublicKeyPath)
            publicKeyPEM, err = os.ReadFile(localPublicKeyPath)
            if err != nil {
                log.Printf("Ошибка локальной загрузки публичного ключа: %v, path=%s", err, localPublicKeyPath)
                session.Values["alert"] = fmt.Sprintf("Публичный ключ не найден: %s", filepath.Base(signedDoc.PublicKeyPath))
                session.Values["alertType"] = "danger"
                session.Save(r, w)
                http.Redirect(w, r, "/verify_document", http.StatusSeeOther)
                return
            }
            log.Printf("Публичный ключ успешно загружен локально: userID=%d, path=%s, размер=%d байт", signature.UserID, localPublicKeyPath, len(publicKeyPEM))
        } else {
            log.Printf("Публичный ключ успешно загружен из HSM: userID=%d, path=%s, размер=%d байт", signature.UserID, hsmPublicKeyPath, len(publicKeyPEM))
        }

        // Логирование содержимого для отладки
        log.Printf("Содержимое подписанного файла: %x", signedData[:min(16, len(signedData))])
        log.Printf("Содержимое подписи: %x", signatureData[:min(16, len(signatureData))])
        log.Printf("Содержимое публичного ключа: %s", string(publicKeyPEM[:min(64, len(publicKeyPEM))]))

        publicKeyBlock, _ := pem.Decode(publicKeyPEM)
        if publicKeyBlock == nil {
            log.Printf("Ошибка декодирования публичного ключа, keyID: %d", keyID)
            utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка декодирования публичного ключа, keyID=%d", keyID))
            session.Values["alert"] = "Ошибка сервера при обработке публичного ключа."
            session.Values["alertType"] = "danger"
            session.Save(r, w)
            http.Redirect(w, r, "/verify_document", http.StatusSeeOther)
            return
        }
        log.Printf("Тип публичного ключа: %s", publicKeyBlock.Type)

        var rsaPublicKey *rsa.PublicKey
        if publicKeyBlock.Type == "RSA PUBLIC KEY" {
            rsaPublicKey, err = x509.ParsePKCS1PublicKey(publicKeyBlock.Bytes)
            if err != nil {
                log.Printf("Ошибка парсинга PKCS#1 публичного ключа: %v, keyID: %d", err, keyID)
                utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка парсинга PKCS#1 публичного ключа, keyID=%d: %v", keyID, err))
                session.Values["alert"] = "Ошибка сервера при обработке публичного ключа."
                session.Values["alertType"] = "danger"
                session.Save(r, w)
                http.Redirect(w, r, "/verify_document", http.StatusSeeOther)
                return
            }
        } else if publicKeyBlock.Type == "PUBLIC KEY" {
            publicKey, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
            if err != nil {
                log.Printf("Ошибка парсинга PKIX публичного ключа: %v, keyID: %d", err, keyID)
                utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка парсинга PKIX публичного ключа, keyID=%d: %v", keyID, err))
                session.Values["alert"] = "Ошибка сервера при обработке публичного ключа."
                session.Values["alertType"] = "danger"
                session.Save(r, w)
                http.Redirect(w, r, "/verify_document", http.StatusSeeOther)
                return
            }
            var ok bool
            rsaPublicKey, ok = publicKey.(*rsa.PublicKey)
            if !ok {
                log.Printf("Публичный ключ не является RSA: keyID: %d", keyID)
                utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Публичный ключ не является RSA, keyID=%d", keyID))
                session.Values["alert"] = "Ошибка сервера: неверный формат ключа."
                session.Values["alertType"] = "danger"
                session.Save(r, w)
                http.Redirect(w, r, "/verify_document", http.StatusSeeOther)
                return
            }
        } else {
            log.Printf("Неподдерживаемый тип публичного ключа: %s, keyID: %d", publicKeyBlock.Type, keyID)
            utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Неподдерживаемый тип публичного ключа: %s, keyID=%d", publicKeyBlock.Type, keyID))
            session.Values["alert"] = "Ошибка сервера: неподдерживаемый тип ключа."
            session.Values["alertType"] = "danger"
            session.Save(r, w)
            http.Redirect(w, r, "/verify_document", http.StatusSeeOther)
            return
        }

        hashed := sha256.Sum256(signedData)
        log.Printf("Хэш файла при проверке: %x", hashed[:])

        err = rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA256, hashed[:], signatureData)
        if err != nil {
            log.Printf("Подпись недействительна: %v, fileID: %d, keyID: %d", err, fileID, keyID)
            utils.LogAction(utils.DB, userID, "verify_document_failed", fmt.Sprintf("Подпись недействительна для файла ID %d с ключом ID %d: %v", fileID, keyID, err))
            session.Values["alert"] = fmt.Sprintf("Подпись недействительна: %v", err)
            session.Values["alertType"] = "danger"
        } else {
            log.Printf("Подпись действительна: fileID: %d, keyID: %d", fileID, keyID)
            utils.LogAction(utils.DB, userID, "verify_document_success", fmt.Sprintf("Подпись действительна для файла ID %d с ключом ID %d", fileID, keyID))
            session.Values["alert"] = "Подпись действительна."
            session.Values["alertType"] = "success"
        }

        session.Save(r, w)
        http.Redirect(w, r, "/verify_document", http.StatusSeeOther)
        return
    }
}

func DeleteSignedDocument(w http.ResponseWriter, r *http.Request) {
    userID, ok := r.Context().Value("userID").(int)
    if !ok || userID == 0 {
        userID = -1
        utils.LogAction(utils.DB, userID, "error", "Неавторизованный доступ к удалению документа")
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }

    log.Println("DeleteSignedDocument handler called")
    utils.LogAction(utils.DB, userID, "delete_signed_document_attempt", fmt.Sprintf("Вызов обработчика DeleteSignedDocument пользователем userID=%d", userID))

    session, _ := utils.Store.Get(r, "alert-session")
    role := r.Context().Value("role").(string)

    if r.Method == http.MethodPost {
        fileID, err := strconv.Atoi(r.FormValue("file_id"))
        if err != nil {
            log.Printf("Неверный ID файла: %v", err)
            utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Неверный ID файла: %v", err))
            session.Values["alert"] = "Неверный ID файла."
            session.Values["alertType"] = "danger"
            session.Save(r, w)
            http.Redirect(w, r, "/verify_document", http.StatusSeeOther)
            return
        }

        keyID, err := strconv.Atoi(r.FormValue("key_id"))
        if err != nil {
            log.Printf("Неверный ID ключа: %v", err)
            utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Неверный ID ключа: %v", err))
            session.Values["alert"] = "Неверный ID ключа."
            session.Values["alertType"] = "danger"
            session.Save(r, w)
            http.Redirect(w, r, "/verify_document", http.StatusSeeOther)
            return
        }

        signedDoc, err := getSignedDocument(fileID, keyID)
        if err != nil {
            log.Printf("Подписанный документ не найден: %v, fileID: %d, keyID: %d", err, fileID, keyID)
            utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Подписанный документ не найден, fileID=%d, keyID=%d: %v", fileID, keyID, err))
            session.Values["alert"] = "Подписанный документ не найден."
            session.Values["alertType"] = "danger"
            session.Save(r, w)
            http.Redirect(w, r, "/verify_document", http.StatusSeeOther)
            return
        }

        signature, err := getSignature(signedDoc.KeyID)
        if err != nil {
            log.Printf("Ключ не найден: %v, keyID: %d", err, keyID)
            utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ключ не найден, keyID=%d: %v", keyID, err))
            session.Values["alert"] = "Ключ не найден."
            session.Values["alertType"] = "danger"
            session.Save(r, w)
            http.Redirect(w, r, "/verify_document", http.StatusSeeOther)
            return
        }

        if role != "admin" && signature.UserID != userID {
            log.Printf("Попытка удаления чужого документа: userID %d, keyID %d", userID, keyID)
            utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Попытка удаления чужого документа, userID=%d, keyID=%d", userID, keyID))
            session.Values["alert"] = "У вас нет прав для удаления этого документа."
            session.Values["alertType"] = "danger"
            session.Save(r, w)
            http.Redirect(w, r, "/verify_document", http.StatusSeeOther)
            return
        }

        // Удаление записи из базы данных
        _, err = utils.DB.Exec("DELETE FROM signed_documents WHERE file_id = ? AND key_id = ?", fileID, keyID)
        if err != nil {
            log.Printf("Ошибка удаления из БД: %v, fileID: %d, keyID: %d", err, fileID, keyID)
            utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка удаления из БД, fileID=%d, keyID=%d: %v", fileID, keyID, err))
            session.Values["alert"] = "Ошибка сервера при удалении данных."
            session.Values["alertType"] = "danger"
            session.Save(r, w)
            http.Redirect(w, r, "/verify_document", http.StatusSeeOther)
            return
        }

        // Локальное удаление файлов (если они существуют)
        for _, path := range []string{signedDoc.SignedFilePath, signedDoc.SignaturePath} {
            err = os.Remove(path)
            if err != nil && !os.IsNotExist(err) {
                log.Printf("Ошибка удаления локального файла %s: %v", path, err)
                utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка удаления локального файла %s: %v", path, err))
            }
        }

        utils.LogAction(utils.DB, userID, "delete_signed_document_success", fmt.Sprintf("Удалён подписанный документ: файл ID %d, ключ ID %d", fileID, keyID))
        session.Values["alert"] = "Подписанный документ успешно удалён."
        session.Values["alertType"] = "success"
        session.Save(r, w)
        http.Redirect(w, r, "/verify_document", http.StatusSeeOther)
        return
    }
}

func renderTemplate(w http.ResponseWriter, r *http.Request, signedDocuments []models.SignedDocument) {
    userID, ok := r.Context().Value("userID").(int)
    if !ok || userID == 0 {
        userID = -1
    }
    utils.LogAction(utils.DB, userID, "render_template_attempt", fmt.Sprintf("Попытка рендеринга шаблона verify_document.html пользователем userID=%d", userID))

    session, _ := utils.Store.Get(r, "alert-session")

    alert, hasAlert := session.Values["alert"].(string)
    alertType, _ := session.Values["alertType"].(string)
    if hasAlert {
        delete(session.Values, "alert")
        delete(session.Values, "alertType")
        session.Save(r, w)
    }

    tmpl, err := template.ParseFiles("templates/verify_document.html")
    if err != nil {
        log.Printf("Ошибка парсинга шаблона: %v", err)
        utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка парсинга шаблона verify_document.html: %v", err))
        http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
        return
    }

    data := struct {
        SignedDocuments []models.SignedDocument
        Alert           string
        AlertType       string
        HasAlert        bool
    }{
        SignedDocuments: signedDocuments,
        Alert:           alert,
        AlertType:       alertType,
        HasAlert:        hasAlert,
    }

    err = tmpl.Execute(w, data)
    if err != nil {
        log.Printf("Ошибка выполнения шаблона: %v", err)
        utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка выполнения шаблона verify_document.html: %v", err))
        http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
        return
    }

    utils.LogAction(utils.DB, userID, "render_template_success", fmt.Sprintf("Успешный рендеринг шаблона verify_document.html пользователем userID=%d", userID))
}

func getSignedDocuments() ([]models.SignedDocument, error) {
    rows, err := utils.DB.Query(`
        SELECT sd.id, sd.file_id, sd.key_id, sd.signed_file_path, sd.signature_path, sd.public_key_path, sd.certificate_path, sd.signed_at, f.filename, s.bank
        FROM signed_documents sd
        JOIN files f ON sd.file_id = f.id
        JOIN signatures s ON sd.key_id = s.id
    `)
    if err != nil {
        utils.LogAction(utils.DB, -1, "error", fmt.Sprintf("Ошибка получения списка всех подписанных документов: %v", err))
        return nil, err
    }
    defer rows.Close()

    var signedDocuments []models.SignedDocument
    for rows.Next() {
        var sd models.SignedDocument
        err := rows.Scan(&sd.ID, &sd.FileID, &sd.KeyID, &sd.SignedFilePath, &sd.SignaturePath, &sd.PublicKeyPath, &sd.CertificatePath, &sd.SignedAt, &sd.Filename, &sd.Bank)
        if err != nil {
            utils.LogAction(utils.DB, -1, "error", fmt.Sprintf("Ошибка сканирования подписанных документов: %v", err))
            return nil, err
        }
        signedDocuments = append(signedDocuments, sd)
    }

    return signedDocuments, nil
}

func getUserSignedDocuments(userID int) ([]models.SignedDocument, error) {
    rows, err := utils.DB.Query(`
        SELECT sd.id, sd.file_id, sd.key_id, sd.signed_file_path, sd.signature_path, sd.public_key_path, sd.certificate_path, sd.signed_at, f.filename, s.bank
        FROM signed_documents sd
        JOIN files f ON sd.file_id = f.id
        JOIN signatures s ON sd.key_id = s.id
        WHERE s.user_id = ?
    `, userID)
    if err != nil {
        utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка получения подписанных документов пользователя userID=%d: %v", userID, err))
        return nil, err
    }
    defer rows.Close()

    var signedDocuments []models.SignedDocument
    for rows.Next() {
        var sd models.SignedDocument
        err := rows.Scan(&sd.ID, &sd.FileID, &sd.KeyID, &sd.SignedFilePath, &sd.SignaturePath, &sd.PublicKeyPath, &sd.CertificatePath, &sd.SignedAt, &sd.Filename, &sd.Bank)
        if err != nil {
            utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка сканирования подписанных документов пользователя userID=%d: %v", userID, err))
            return nil, err
        }
        signedDocuments = append(signedDocuments, sd)
    }

    return signedDocuments, nil
}

func getSignedDocumentsByFilename(filename string) ([]models.SignedDocument, error) {
    rows, err := utils.DB.Query(`
        SELECT sd.id, sd.file_id, sd.key_id, sd.signed_file_path, sd.signature_path, sd.public_key_path, sd.certificate_path, sd.signed_at, f.filename, s.bank
        FROM signed_documents sd
        JOIN files f ON sd.file_id = f.id
        JOIN signatures s ON sd.key_id = s.id
        WHERE f.filename LIKE ?
    `, "%"+filename+"%")
    if err != nil {
        utils.LogAction(utils.DB, -1, "error", fmt.Sprintf("Ошибка поиска документов по имени файла '%s': %v", filename, err))
        return nil, err
    }
    defer rows.Close()

    var signedDocuments []models.SignedDocument
    for rows.Next() {
        var sd models.SignedDocument
        err := rows.Scan(&sd.ID, &sd.FileID, &sd.KeyID, &sd.SignedFilePath, &sd.SignaturePath, &sd.PublicKeyPath, &sd.CertificatePath, &sd.SignedAt, &sd.Filename, &sd.Bank)
        if err != nil {
            utils.LogAction(utils.DB, -1, "error", fmt.Sprintf("Ошибка сканирования документов по имени файла '%s': %v", filename, err))
            return nil, err
        }
        signedDocuments = append(signedDocuments, sd)
    }

    return signedDocuments, nil
}

func getUserSignedDocumentsByFilename(userID int, filename string) ([]models.SignedDocument, error) {
    rows, err := utils.DB.Query(`
        SELECT sd.id, sd.file_id, sd.key_id, sd.signed_file_path, sd.signature_path, sd.public_key_path, sd.certificate_path, sd.signed_at, f.filename, s.bank
        FROM signed_documents sd
        JOIN files f ON sd.file_id = f.id
        JOIN signatures s ON sd.key_id = s.id
        WHERE s.user_id = ? AND f.filename LIKE ?
    `, userID, "%"+filename+"%")
    if err != nil {
        utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка поиска документов пользователя userID=%d по имени файла '%s': %v", userID, filename, err))
        return nil, err
    }
    defer rows.Close()

    var signedDocuments []models.SignedDocument
    for rows.Next() {
        var sd models.SignedDocument
        err := rows.Scan(&sd.ID, &sd.FileID, &sd.KeyID, &sd.SignedFilePath, &sd.SignaturePath, &sd.PublicKeyPath, &sd.CertificatePath, &sd.SignedAt, &sd.Filename, &sd.Bank)
        if err != nil {
            utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка сканирования документов пользователя userID=%d по имени файла '%s': %v", userID, filename, err))
            return nil, err
        }
        signedDocuments = append(signedDocuments, sd)
    }

    return signedDocuments, nil
}

func getSignedDocument(fileID, keyID int) (models.SignedDocument, error) {
    var sd models.SignedDocument
    err := utils.DB.QueryRow(`
        SELECT sd.id, sd.file_id, sd.key_id, sd.signed_file_path, sd.signature_path, sd.public_key_path, sd.certificate_path, sd.signed_at, f.filename, s.bank
        FROM signed_documents sd
        JOIN files f ON sd.file_id = f.id
        JOIN signatures s ON sd.key_id = s.id
        WHERE sd.file_id = ? AND sd.key_id = ?
    `, fileID, keyID).Scan(&sd.ID, &sd.FileID, &sd.KeyID, &sd.SignedFilePath, &sd.SignaturePath, &sd.PublicKeyPath, &sd.CertificatePath, &sd.SignedAt, &sd.Filename, &sd.Bank)
    if err != nil {
        utils.LogAction(utils.DB, -1, "error", fmt.Sprintf("Ошибка получения подписанного документа, fileID=%d, keyID=%d: %v", fileID, keyID, err))
        return sd, err
    }
    return sd, nil
}

func getSignature(keyID int) (models.Signature, error) {
    var signature models.Signature
    var publicKeyPath, privateKeyPath, certificatePath *string
    err := utils.DB.QueryRow("SELECT id, user_id, bank, public_key_path, private_key_path, certificate_path FROM signatures WHERE id = ?", keyID).Scan(
        &signature.ID,
        &signature.UserID,
        &signature.Bank,
        &publicKeyPath,
        &privateKeyPath,
        &certificatePath,
    )
    if err != nil {
        utils.LogAction(utils.DB, -1, "error", fmt.Sprintf("Ошибка получения подписи, keyID=%d: %v", keyID, err))
        return signature, err
    }
    signature.PublicKeyPath = publicKeyPath
    signature.PrivateKeyPath = privateKeyPath
    signature.CertificatePath = certificatePath
    return signature, nil
}