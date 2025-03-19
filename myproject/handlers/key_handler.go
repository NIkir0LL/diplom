package handlers

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "html/template"
    "math/big"
    "myproject/models"
    "myproject/utils"
    "net/http"
    "os"
    "path/filepath"
    "strconv"
    "time"
)

func GenerateKey(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodPost {
        userID, err := strconv.Atoi(r.FormValue("user_id"))
        if err != nil {
            http.Error(w, "Invalid user ID", http.StatusBadRequest)
            return
        }

        bank := r.FormValue("bank")

        // Генерация ключевой пары
        privateKey, publicKey, err := utils.GenerateKeyPair()
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        // Создание папки для хранения ключей
        keyDir := filepath.Join("keys", strconv.Itoa(userID)+"_"+bank) // Папка будет называться, например, "keys/1_bankname"
        err = os.MkdirAll(keyDir, os.ModePerm) // Создаем папку, если она не существует
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        // Имена файлов (без пути)
        publicKeyFile := "public.pem"
        privateKeyFile := "private.pem"
        certificateFile := "certificate.pem"

        // Полные пути к файлам
        publicKeyPath := filepath.Join(keyDir, publicKeyFile)
        privateKeyPath := filepath.Join(keyDir, privateKeyFile)
        certificatePath := filepath.Join(keyDir, certificateFile)

        // Сохранение публичного ключа
        err = utils.SavePublicKeyToFile(publicKey, publicKeyPath)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        // Сохранение приватного ключа
        err = utils.SaveKeyToFile(privateKey, privateKeyPath)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        // Генерация сертификата
        cert, err := generateCertificate(privateKey, publicKey)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        // Сохранение сертификата
        err = os.WriteFile(certificatePath, cert, 0644)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        // Сохранение информации в базу данных (только имена файлов)
        _, err = utils.DB.Exec("INSERT INTO signatures (user_id, bank, public_key_path, private_key_path, certificate_path) VALUES (?, ?, ?, ?, ?)",
            userID, bank, publicKeyFile, privateKeyFile, certificateFile)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        http.Redirect(w, r, "/generate_key", http.StatusSeeOther)
        return
    }

    // Получение списка пользователей и ключей
    users, err := getUsersForKeyGeneration()
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    keys, err := getAllKeys()
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    // Рендеринг шаблона
    tmpl, err := template.ParseFiles("templates/generate_key.html")
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

    data := struct {
        Users []models.User
        Keys  []models.Key
    }{
        Users: users,
        Keys:  keys,
    }

    tmpl.Execute(w, data)
}

func DeleteKey(w http.ResponseWriter, r *http.Request) {
    if r.Method == http.MethodPost {
        keyID, err := strconv.Atoi(r.FormValue("key_id"))
        if err != nil {
            http.Error(w, "Invalid key ID", http.StatusBadRequest)
            return
        }

        key, err := getKeyByID(keyID)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        // Формируем полные пути к файлам
        keyDir := filepath.Join("keys", strconv.Itoa(key.UserID)+"_"+key.Bank)
        publicKeyPath := filepath.Join(keyDir, key.PublicKeyPath)
        privateKeyPath := filepath.Join(keyDir, key.PrivateKeyPath)
        certificatePath := filepath.Join(keyDir, key.CertificatePath)

        // Удаление файлов
        err = os.Remove(publicKeyPath)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        err = os.Remove(privateKeyPath)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        err = os.Remove(certificatePath)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        // Удаление папки, если она пуста
        err = os.Remove(keyDir) // Удаляем папку
        if err != nil && !os.IsNotExist(err) {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        // Удаление записи из базы данных
        _, err = utils.DB.Exec("DELETE FROM signatures WHERE id = ?", keyID)
        if err != nil {
            http.Error(w, err.Error(), http.StatusInternalServerError)
            return
        }

        http.Redirect(w, r, "/generate_key", http.StatusSeeOther)
        return
    }
}

func getAllKeys() ([]models.Key, error) {
    rows, err := utils.DB.Query("SELECT s.id, s.user_id, u.login, s.bank, s.public_key_path, s.private_key_path, s.certificate_path FROM signatures s JOIN users u ON s.user_id = u.id")
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var keys []models.Key
    for rows.Next() {
        var key models.Key
        err := rows.Scan(&key.ID, &key.UserID, &key.UserName, &key.Bank, &key.PublicKeyPath, &key.PrivateKeyPath, &key.CertificatePath)
        if err != nil {
            return nil, err
        }
        keys = append(keys, key)
    }

    return keys, nil
}

func getKeyByID(keyID int) (models.Key, error) {
    var key models.Key
    err := utils.DB.QueryRow("SELECT s.id, s.user_id, u.login, s.bank, s.public_key_path, s.private_key_path, s.certificate_path FROM signatures s JOIN users u ON s.user_id = u.id WHERE s.id = ?", keyID).
        Scan(&key.ID, &key.UserID, &key.UserName, &key.Bank, &key.PublicKeyPath, &key.PrivateKeyPath, &key.CertificatePath)
    if err != nil {
        return key, err
    }
    return key, nil
}

func getUsersForKeyGeneration() ([]models.User, error) {
    rows, err := utils.DB.Query("SELECT id, login FROM users")
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var users []models.User
    for rows.Next() {
        var user models.User
        err := rows.Scan(&user.ID, &user.Login)
        if err != nil {
            return nil, err
        }
        users = append(users, user)
    }

    return users, nil
}

func generateCertificate(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) ([]byte, error) {
    template := x509.Certificate{
        SerialNumber: big.NewInt(1),
        Subject: pkix.Name{
            CommonName: "example.com",
        },
        NotBefore: time.Now(),
        NotAfter:  time.Now().AddDate(1, 0, 0),
        KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
        ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
        BasicConstraintsValid: true,
    }

    derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
    if err != nil {
        return nil, err
    }

    certPEM := pem.EncodeToMemory(&pem.Block{
        Type:  "CERTIFICATE",
        Bytes: derBytes,
    })

    return certPEM, nil
}