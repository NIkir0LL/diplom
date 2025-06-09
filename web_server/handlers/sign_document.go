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
    "net/url"
    "path/filepath"
    "strconv"
    "strings"
    "time"
)

func SignDocument(w http.ResponseWriter, r *http.Request) {
    userID, ok := r.Context().Value("userID").(int)
    if !ok || userID == 0 {
        userID = -1
        utils.LogAction(utils.DB, userID, "error", "Неавторизованный доступ к подписи документа")
        http.Redirect(w, r, "/login", http.StatusSeeOther)
        return
    }
    role := r.Context().Value("role").(string)
    session, _ := utils.Store.Get(r, "alert-session")

    if r.Method == http.MethodGet {
        utils.LogAction(utils.DB, userID, "view_sign_document_attempt", fmt.Sprintf("Попытка просмотра страницы подписи документа пользователем userID=%d", userID))

        searchFile := r.URL.Query().Get("search_file")
        searchKey := r.URL.Query().Get("search_key")

        var files []models.File
        var keys []models.Key
        var err error

        if searchFile != "" {
            if role == "admin" {
                files, err = getFilesByFilename(searchFile)
            } else {
                files, err = getUserFilesByFilename(userID, searchFile)
            }
            if err != nil {
                log.Printf("Ошибка поиска файлов: %v, search: %s", err, searchFile)
                utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка поиска файлов по названию '%s': %v", searchFile, err))
                session.Values["alert"] = "Ошибка при поиске файлов."
                session.Values["alertType"] = "danger"
                session.Save(r, w)
            } else if len(files) == 0 {
                session.Values["alert"] = fmt.Sprintf("Файлы с названием, содержащим \"%s\", не найдены.", searchFile)
                session.Values["alertType"] = "danger"
                session.Save(r, w)
            }
        } else {
            if role == "admin" {
                files, err = getSignDocAllFiles()
            } else {
                files, err = getSignDocUserFiles(userID)
            }
            if err != nil {
                log.Printf("Ошибка получения файлов: %v", err)
                utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка получения списка файлов: %v", err))
                session.Values["alert"] = "Ошибка при загрузке файлов."
                session.Values["alertType"] = "danger"
                session.Save(r, w)
            }
        }

        if searchKey != "" {
            if role == "admin" {
                keys, err = getKeysByBank(searchKey)
            } else {
                keys, err = getUserKeysByBank(userID, searchKey)
            }
            if err != nil {
                log.Printf("Ошибка поиска ключей: %v, search: %s", err, searchKey)
                utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка поиска ключей по названию '%s': %v", searchKey, err))
                session.Values["alert"] = "Ошибка при поиске ключей."
                session.Values["alertType"] = "danger"
                session.Save(r, w)
            } else if len(keys) == 0 {
                session.Values["alert"] = fmt.Sprintf("Ключи с названием, содержащим \"%s\", не найдены.", searchKey)
                session.Values["alertType"] = "danger"
                session.Save(r, w)
            }
        } else {
            if role == "admin" {
                keys, err = getSignDocAllKeys()
            } else {
                keys, err = getUserKeys(userID)
            }
            if err != nil {
                log.Printf("Ошибка получения ключей: %v", err)
                utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка получения списка ключей: %v", err))
                session.Values["alert"] = "Ошибка при загрузке ключей."
                session.Values["alertType"] = "danger"
                session.Save(r, w)
            }
        }

        alert, hasAlert := session.Values["alert"].(string)
        alertType, _ := session.Values["alertType"].(string)
        if hasAlert {
            delete(session.Values, "alert")
            delete(session.Values, "alertType")
            session.Save(r, w)
        }

        tmpl := template.Must(template.ParseFiles("templates/sign_document.html"))
        data := struct {
            Files      []models.File
            Keys       []models.Key
            Alert      string
            AlertType  string
            HasAlert   bool
            SearchFile string
            SearchKey  string
        }{
            Files:      files,
            Keys:       keys,
            Alert:      alert,
            AlertType:  alertType,
            HasAlert:   hasAlert,
            SearchFile: searchFile,
            SearchKey:  searchKey,
        }

        err = tmpl.Execute(w, data)
        if err != nil {
            log.Printf("Ошибка рендеринга шаблона: %v", err)
            utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка рендеринга шаблона sign_document.html: %v", err))
            http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
            return
        }
        utils.LogAction(utils.DB, userID, "render_sign_document_success", fmt.Sprintf("Успешный рендеринг страницы подписи документа пользователем userID=%d", userID))
        return
    }

    if r.Method == http.MethodPost {
        utils.LogAction(utils.DB, userID, "sign_document_attempt", fmt.Sprintf("Попытка подписи документа пользователем userID=%d", userID))

        fileIDStr := r.FormValue("file_id")
        keyIDStr := r.FormValue("key_id")
        searchFile := r.FormValue("search_file")
        searchKey := r.FormValue("search_key")

        if fileIDStr == "" {
            log.Printf("Файл не выбран")
            session.Values["alert"] = "Выберите файл для подписи."
            session.Values["alertType"] = "danger"
            session.Save(r, w)
            redirectURL := "/sign_document"
            if searchFile != "" || searchKey != "" {
                redirectURL += "?"
                if searchFile != "" {
                    redirectURL += "search_file=" + url.QueryEscape(searchFile)
                }
                if searchKey != "" {
                    if searchFile != "" {
                        redirectURL += "&"
                    }
                    redirectURL += "search_key=" + url.QueryEscape(searchKey)
                }
            }
            http.Redirect(w, r, redirectURL, http.StatusSeeOther)
            return
        }

        if keyIDStr == "" {
            log.Printf("Ключ не выбран")
            session.Values["alert"] = "Выберите ключ для подписи."
            session.Values["alertType"] = "danger"
            session.Save(r, w)
            redirectURL := "/sign_document"
            if searchFile != "" || searchKey != "" {
                redirectURL += "?"
                if searchFile != "" {
                    redirectURL += "search_file=" + url.QueryEscape(searchFile)
                }
                if searchKey != "" {
                    if searchFile != "" {
                        redirectURL += "&"
                    }
                    redirectURL += "search_key=" + url.QueryEscape(searchKey)
                }
            }
            http.Redirect(w, r, redirectURL, http.StatusSeeOther)
            return
        }

        fileID, err := strconv.Atoi(fileIDStr)
        if err != nil {
            log.Printf("Неверный ID файла: %v", err)
            session.Values["alert"] = "Неверный ID файла."
            session.Values["alertType"] = "danger"
            session.Save(r, w)
            http.Redirect(w, r, "/sign_document", http.StatusSeeOther)
            return
        }

        keyID, err := strconv.Atoi(keyIDStr)
        if err != nil {
            log.Printf("Неверный ID ключа: %v", err)
            session.Values["alert"] = "Неверный ID ключа."
            session.Values["alertType"] = "danger"
            session.Save(r, w)
            http.Redirect(w, r, "/sign_document", http.StatusSeeOther)
            return
        }

        var file models.File
        err = utils.DB.QueryRow("SELECT id, filename, filepath, user_id FROM files WHERE id=?", fileID).Scan(&file.ID, &file.Filename, &file.Filepath, &file.UserID)
        if err != nil {
            log.Printf("Файл не найден: %v, fileID: %d", err, fileID)
            session.Values["alert"] = "Файл не найден."
            session.Values["alertType"] = "danger"
            session.Save(r, w)
            http.Redirect(w, r, "/sign_document", http.StatusSeeOther)
            return
        }

        if role != "admin" && file.UserID != userID {
            log.Printf("Попытка подписи чужого файла: userID %d, fileID %d", userID, fileID)
            session.Values["alert"] = "У вас нет прав для подписи этого файла."
            session.Values["alertType"] = "danger"
            session.Save(r, w)
            http.Redirect(w, r, "/sign_document", http.StatusSeeOther)
            return
        }

        var key models.Key
        err = utils.DB.QueryRow("SELECT id, user_id, bank, public_key_path, private_key_path, certificate_path FROM signatures WHERE id=?", keyID).Scan(&key.ID, &key.UserID, &key.Bank, &key.PublicKeyPath, &key.PrivateKeyPath, &key.CertificatePath)
        if err != nil {
            log.Printf("Ключ не найден: %v, keyID: %d", err, keyID)
            session.Values["alert"] = "Ключ не найден."
            session.Values["alertType"] = "danger"
            session.Save(r, w)
            http.Redirect(w, r, "/sign_document", http.StatusSeeOther)
            return
        }

        if role != "admin" && key.UserID != userID {
            log.Printf("Попытка использования чужого ключа: userID %d, keyID %d", userID, keyID)
            session.Values["alert"] = "У вас нет прав для использования этого ключа."
            session.Values["alertType"] = "danger"
            session.Save(r, w)
            http.Redirect(w, r, "/sign_document", http.StatusSeeOther)
            return
        }

        // Формирование пути для HSM
        hsmPath := file.Filepath
        log.Printf("Исходный filepath из базы данных: %s", hsmPath)
        if !strings.HasPrefix(hsmPath, "/files/") {
            hsmPath = filepath.Join("/files", file.Filename)
        }

        // Загрузка файла из HSM
        log.Printf("Попытка запроса файла из HSM: userID=%s, type=file, path=%s", strconv.Itoa(file.UserID), hsmPath)
        fileData, err := hsm.Retrieve(strconv.Itoa(file.UserID), "file", hsmPath)
        if err != nil {
            log.Printf("Ошибка загрузки файла из HSM: %v, userID=%d, path=%s", err, file.UserID, hsmPath)
            session.Values["alert"] = fmt.Sprintf("Файл не найден: %s", file.Filename)
            session.Values["alertType"] = "danger"
            session.Save(r, w)
            http.Redirect(w, r, "/sign_document", http.StatusSeeOther)
            return
        }
        log.Printf("Файл успешно загружен из HSM: userID=%d, path=%s, размер=%d байт", file.UserID, hsmPath, len(fileData))

        // Вычисление хэша файла
        hashed := sha256.Sum256(fileData)
        log.Printf("Хэш файла при подписи: %x", hashed[:])

        // Проверка приватного ключа
        log.Printf("Приватный ключ для подписи: %s", key.PrivateKeyPath)

        // Загрузка публичного ключа из HSM для локальной верификации
        log.Printf("Попытка загрузки публичного ключа из HSM: path=%s", key.PublicKeyPath)
        publicKeyData, err := hsm.Retrieve(strconv.Itoa(key.UserID), "key", key.PublicKeyPath)
        if err != nil {
            log.Printf("Ошибка загрузки публичного ключа из HSM: %v, path=%s", err, key.PublicKeyPath)
            session.Values["alert"] = "Ошибка загрузки публичного ключа."
            session.Values["alertType"] = "danger"
            session.Save(r, w)
            http.Redirect(w, r, "/sign_document", http.StatusSeeOther)
            return
        }
        log.Printf("Публичный ключ успешно загружен из HSM: path=%s, размер=%d байт", key.PublicKeyPath, len(publicKeyData))

        // Выполнение подписи через HSM
        signatureData, err := hsm.Sign(strconv.Itoa(key.UserID), "key", key.PrivateKeyPath, key.PublicKeyPath, hashed[:])
        if err != nil {
            log.Printf("Ошибка подписи файла через HSM: %v, fileID: %d, keyID: %d", err, fileID, keyID)
            session.Values["alert"] = "Ошибка сервера при подписи файла."
            session.Values["alertType"] = "danger"
            session.Save(r, w)
            http.Redirect(w, r, "/sign_document", http.StatusSeeOther)
            return
        }
        log.Printf("Подпись через HSM успешна: размер=%d байт", len(signatureData))
        log.Printf("Содержимое подписи: %x", signatureData[:min(16, len(signatureData))])

        // Локальная верификация подписи для отладки
        publicKeyBlock, _ := pem.Decode(publicKeyData)
        if publicKeyBlock == nil {
            log.Printf("Ошибка декодирования публичного ключа: path=%s", key.PublicKeyPath)
            session.Values["alert"] = "Ошибка обработки публичного ключа."
            session.Values["alertType"] = "danger"
            session.Save(r, w)
            http.Redirect(w, r, "/sign_document", http.StatusSeeOther)
            return
        }
        publicKey, err := x509.ParsePKCS1PublicKey(publicKeyBlock.Bytes)
        if err != nil {
            log.Printf("Ошибка парсинга публичного ключа: %v, path=%s", err, key.PublicKeyPath)
            session.Values["alert"] = "Ошибка обработки публичного ключа."
            session.Values["alertType"] = "danger"
            session.Save(r, w)
            http.Redirect(w, r, "/sign_document", http.StatusSeeOther)
            return
        }
        err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signatureData)
        if err != nil {
            log.Printf("Локальная верификация подписи не удалась: %v", err)
        } else {
            log.Printf("Локальная верификация подписи успешна")
        }

        // Формирование пути для сохранения подписи в HSM
        signatureHSMPath := filepath.Join("/signatures", strconv.Itoa(key.UserID), fmt.Sprintf("signature_%s.sig", file.Filename))
        log.Printf("Сохранение подписи в HSM: userID=%s, type=signature, path=%s", strconv.Itoa(key.UserID), signatureHSMPath)

        // Сохранение подписи в HSM
        err = hsm.Store(strconv.Itoa(key.UserID), "signature", signatureHSMPath, signatureData)
        if err != nil {
            log.Printf("Ошибка сохранения подписи в HSM: %v, path: %s", err, signatureHSMPath)
            session.Values["alert"] = "Ошибка сервера при сохранении подписи."
            session.Values["alertType"] = "danger"
            session.Save(r, w)
            http.Redirect(w, r, "/sign_document", http.StatusSeeOther)
            return
        }
        log.Printf("Подпись успешно сохранена в HSM: path=%s", signatureHSMPath)

        // Формирование пути для сохранения подписанного файла в HSM
        signedFileHSMPath := filepath.Join("/files/signed", strconv.Itoa(key.UserID), fmt.Sprintf("signed_%s", file.Filename))
        log.Printf("Сохранение подписанного файла в HSM: userID=%s, type=file, path=%s", strconv.Itoa(key.UserID), signedFileHSMPath)

        // Сохранение подписанного файла в HSM
        err = hsm.Store(strconv.Itoa(key.UserID), "file", signedFileHSMPath, fileData)
        if err != nil {
            log.Printf("Ошибка сохранения подписанного файла в HSM: %v, path: %s", err, signedFileHSMPath)
            session.Values["alert"] = "Ошибка сервера при сохранении подписанного файла."
            session.Values["alertType"] = "danger"
            session.Save(r, w)
            http.Redirect(w, r, "/sign_document", http.StatusSeeOther)
            return
        }
        log.Printf("Подписанный файл успешно сохранен в HSM: path=%s", signedFileHSMPath)

        // Запись в базу данных
        signedAt := time.Now()
        _, err = utils.DB.Exec("INSERT INTO signed_documents (file_id, key_id, signed_file_path, signature_path, public_key_path, certificate_path, signed_at) VALUES (?, ?, ?, ?, ?, ?, ?)", 
            fileID, keyID, signedFileHSMPath, signatureHSMPath, key.PublicKeyPath, key.CertificatePath, signedAt)
        if err != nil {
            log.Printf("Ошибка записи в БД: %v, fileID: %d, keyID: %d", err, fileID, keyID)
            session.Values["alert"] = "Ошибка сервера при сохранении данных."
            session.Values["alertType"] = "danger"
            session.Save(r, w)
            http.Redirect(w, r, "/sign_document", http.StatusSeeOther)
            return
        }

        utils.LogAction(utils.DB, userID, "sign_document_success", fmt.Sprintf("Подписан файл ID %d с ключом ID %d, подпись сохранена в HSM по пути %s, подписанный файл сохранен в HSM по пути %s", fileID, keyID, signatureHSMPath, signedFileHSMPath))
        session.Values["alert"] = "Документ успешно подписан и сохранен."
        session.Values["alertType"] = "success"
        session.Save(r, w)
        http.Redirect(w, r, "/verify_document", http.StatusSeeOther)
        return
    }
}

// Остальные функции (getFilesByFilename, getUserFilesByFilename, и т.д.) остаются без изменений
// getFilesByFilename возвращает все файлы, чьи имена содержат заданную подстроку (для админов).
func getFilesByFilename(filename string) ([]models.File, error) {
    rows, err := utils.DB.Query("SELECT id, filename, filepath, user_id FROM files WHERE filename LIKE ?", "%"+filename+"%")
    if err != nil {
        utils.LogAction(utils.DB, -1, "error", fmt.Sprintf("Ошибка поиска файлов по имени '%s': %v", filename, err))
        return nil, err
    }
    defer rows.Close()

    var files []models.File
    for rows.Next() {
        var f models.File
        if err := rows.Scan(&f.ID, &f.Filename, &f.Filepath, &f.UserID); err != nil {
            utils.LogAction(utils.DB, -1, "error", fmt.Sprintf("Ошибка сканирования файлов по имени '%s': %v", filename, err))
            return nil, err
        }
        files = append(files, f)
    }
    return files, nil
}

// getUserFilesByFilename возвращает файлы пользователя, чьи имена содержат заданную подстроку.
func getUserFilesByFilename(userID int, filename string) ([]models.File, error) {
    rows, err := utils.DB.Query("SELECT id, filename, filepath, user_id FROM files WHERE user_id = ? AND filename LIKE ?", userID, "%"+filename+"%")
    if err != nil {
        utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка поиска файлов пользователя userID=%d по имени '%s': %v", userID, filename, err))
        return nil, err
    }
    defer rows.Close()

    var files []models.File
    for rows.Next() {
        var f models.File
        if err := rows.Scan(&f.ID, &f.Filename, &f.Filepath, &f.UserID); err != nil {
            utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка сканирования файлов пользователя userID=%d по имени '%s': %v", userID, filename, err))
            return nil, err
        }
        files = append(files, f)
    }
    return files, nil
}

// getSignDocAllFiles возвращает все файлы (для админов).
func getSignDocAllFiles() ([]models.File, error) {
    rows, err := utils.DB.Query("SELECT id, filename, filepath, user_id FROM files")
    if err != nil {
        utils.LogAction(utils.DB, -1, "error", fmt.Sprintf("Ошибка получения всех файлов: %v", err))
        return nil, err
    }
    defer rows.Close()

    var files []models.File
    for rows.Next() {
        var f models.File
        if err := rows.Scan(&f.ID, &f.Filename, &f.Filepath, &f.UserID); err != nil {
            utils.LogAction(utils.DB, -1, "error", fmt.Sprintf("Ошибка сканирования всех файлов: %v", err))
            return nil, err
        }
        files = append(files, f)
    }
    return files, nil
}

// getSignDocUserFiles возвращает файлы конкретного пользователя.
func getSignDocUserFiles(userID int) ([]models.File, error) {
    rows, err := utils.DB.Query("SELECT id, filename, filepath, user_id FROM files WHERE user_id = ?", userID)
    if err != nil {
        utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка получения файлов пользователя userID=%d: %v", userID, err))
        return nil, err
    }
    defer rows.Close()

    var files []models.File
    for rows.Next() {
        var f models.File
        if err := rows.Scan(&f.ID, &f.Filename, &f.Filepath, &f.UserID); err != nil {
            utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка сканирования файлов пользователя userID=%d: %v", userID, err))
            return nil, err
        }
        files = append(files, f)
    }
    return files, nil
}

// getSignDocAllKeys возвращает все ключи (для админов).
func getSignDocAllKeys() ([]models.Key, error) {
    rows, err := utils.DB.Query("SELECT id, user_id, bank, public_key_path, private_key_path, certificate_path FROM signatures")
    if err != nil {
        utils.LogAction(utils.DB, -1, "error", fmt.Sprintf("Ошибка получения всех ключей: %v", err))
        return nil, err
    }
    defer rows.Close()

    var keys []models.Key
    for rows.Next() {
        var k models.Key
        if err := rows.Scan(&k.ID, &k.UserID, &k.Bank, &k.PublicKeyPath, &k.PrivateKeyPath, &k.CertificatePath); err != nil {
            utils.LogAction(utils.DB, -1, "error", fmt.Sprintf("Ошибка сканирования всех ключей: %v", err))
            return nil, err
        }
        keys = append(keys, k)
    }
    return keys, nil
}

// getUserKeys возвращает ключи конкретного пользователя.
func getUserKeys(userID int) ([]models.Key, error) {
    rows, err := utils.DB.Query("SELECT id, user_id, bank, public_key_path, private_key_path, certificate_path FROM signatures WHERE user_id = ?", userID)
    if err != nil {
        utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка получения ключей пользователя userID=%d: %v", userID, err))
        return nil, err
    }
    defer rows.Close()

    var keys []models.Key
    for rows.Next() {
        var k models.Key
        if err := rows.Scan(&k.ID, &k.UserID, &k.Bank, &k.PublicKeyPath, &k.PrivateKeyPath, &k.CertificatePath); err != nil {
            utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка сканирования ключей пользователя userID=%d: %v", userID, err))
            return nil, err
        }
        keys = append(keys, k)
    }
    return keys, nil
}

// getKeysByBank возвращает все ключи, чьи банки содержат заданную подстроку (для админов).
func getKeysByBank(bank string) ([]models.Key, error) {
    rows, err := utils.DB.Query("SELECT id, user_id, bank, public_key_path, private_key_path, certificate_path FROM signatures WHERE bank LIKE ?", "%"+bank+"%")
    if err != nil {
        utils.LogAction(utils.DB, -1, "error", fmt.Sprintf("Ошибка поиска ключей по названию '%s': %v", bank, err))
        return nil, err
    }
    defer rows.Close()

    var keys []models.Key
    for rows.Next() {
        var k models.Key
        if err := rows.Scan(&k.ID, &k.UserID, &k.Bank, &k.PublicKeyPath, &k.PrivateKeyPath, &k.CertificatePath); err != nil {
            utils.LogAction(utils.DB, -1, "error", fmt.Sprintf("Ошибка сканирования ключей по названию '%s': %v", bank, err))
            return nil, err
        }
        keys = append(keys, k)
    }
    return keys, nil
}

// getUserKeysByBank возвращает ключи пользователя, чьи банки содержат заданную подстроку.
func getUserKeysByBank(userID int, bank string) ([]models.Key, error) {
    rows, err := utils.DB.Query("SELECT id, user_id, bank, public_key_path, private_key_path, certificate_path FROM signatures WHERE user_id = ? AND bank LIKE ?", userID, "%"+bank+"%")
    if err != nil {
        utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка поиска ключей пользователя userID=%d по названию '%s': %v", userID, bank, err))
        return nil, err
    }
    defer rows.Close()

    var keys []models.Key
    for rows.Next() {
        var k models.Key
        if err := rows.Scan(&k.ID, &k.UserID, &k.Bank, &k.PublicKeyPath, &k.PrivateKeyPath, &k.CertificatePath); err != nil {
            utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка сканирования ключей пользователя userID=%d по названию '%s': %v", userID, bank, err))
            return nil, err
        }
        keys = append(keys, k)
    }
    return keys, nil
}