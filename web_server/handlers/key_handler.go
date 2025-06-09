package handlers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"html/template"
	"log"
	"math/big"
	"myproject/hsm"
	"myproject/models"
	"myproject/utils"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Глобальные переменные для корневого и промежуточного CA
var (
	rootPrivateKey         *rsa.PrivateKey
	rootCert               *x509.Certificate
	intermediatePrivateKey *rsa.PrivateKey
	intermediateCert       *x509.Certificate
)

func init() {
	var err error
	// Пробуем загрузить корневой CA из HSM
	log.Printf("Попытка загрузки корневого CA из HSM")
	rootPrivateKey, rootCert, err = loadRootCA()
	if err != nil {
		log.Printf("Корневой CA не найден, генерируем новый: %v", err)
		rootPrivateKey, rootCert, err = generateRootCA()
		if err != nil {
			log.Fatalf("Ошибка генерации корневого CA: %v", err)
		}
	}

	// Пробуем загрузить промежуточный CA из HSM
	log.Printf("Попытка загрузки промежуточного CA из HSM")
	intermediatePrivateKey, intermediateCert, err = loadIntermediateCA()
	if err != nil {
		log.Printf("Промежуточный CA не найден, генерируем новый: %v", err)
		intermediatePrivateKey, intermediateCert, err = generateIntermediateCA(rootPrivateKey, rootCert)
		if err != nil {
			log.Fatalf("Ошибка генерации промежуточного CA: %v", err)
		}
	}

	// Проверяем цепочку доверия между корневым и промежуточным CA
	log.Printf("Проверка цепочки доверия промежуточного CA")
	err = verifyIntermediateCA(intermediateCert, rootCert)
	if err != nil {
		log.Fatalf("Промежуточный CA недействителен: %v. Требуется перегенерация.", err)
	}
	log.Printf("Цепочка доверия подтверждена")
}

// Функция для загрузки корневого CA из HSM
func loadRootCA() (*rsa.PrivateKey, *x509.Certificate, error) {
	privKeyData, err := hsm.Retrieve("system", "key", "/root_key.pem")
	if err != nil {
		return nil, nil, fmt.Errorf("не удалось извлечь /root_key.pem из HSM: %v", err)
	}
	privKeyBlock, _ := pem.Decode(privKeyData)
	if privKeyBlock == nil || privKeyBlock.Type != "RSA PRIVATE KEY" {
		return nil, nil, fmt.Errorf("неверный формат приватного ключа в /root_key.pem")
	}
	privKey, err := x509.ParsePKCS1PrivateKey(privKeyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("ошибка парсинга приватного ключа: %v", err)
	}

	certData, err := hsm.Retrieve("system", "cert", "/root_cert.pem")
	if err != nil {
		return nil, nil, fmt.Errorf("не удалось извлечь /root_cert.pem из HSM: %v", err)
	}
	certBlock, _ := pem.Decode(certData)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("неверный формат сертификата в /root_cert.pem")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("ошибка парсинга сертификата: %v", err)
	}

	return privKey, cert, nil
}

// Функция для загрузки промежуточного CA из HSM
func loadIntermediateCA() (*rsa.PrivateKey, *x509.Certificate, error) {
	log.Printf("Загрузка /intermediate_key.pem из HSM для user_id=system, type=key")
	privKeyData, err := hsm.Retrieve("system", "key", "/intermediate_key.pem")
	if err != nil {
		log.Printf("Ошибка загрузки /intermediate_key.pem: %v", err)
		return nil, nil, fmt.Errorf("не удалось извлечь /intermediate_key.pem из HSM: %v", err)
	}
	privKeyBlock, _ := pem.Decode(privKeyData)
	if privKeyBlock == nil || privKeyBlock.Type != "RSA PRIVATE KEY" {
		log.Printf("Неверный формат приватного ключа в /intermediate_key.pem")
		return nil, nil, fmt.Errorf("неверный формат приватного ключа в /intermediate_key.pem")
	}
	privKey, err := x509.ParsePKCS1PrivateKey(privKeyBlock.Bytes)
	if err != nil {
		log.Printf("Ошибка парсинга приватного ключа: %v", err)
		return nil, nil, fmt.Errorf("ошибка парсинга приватного ключа: %v", err)
	}

	log.Printf("Загрузка /intermediate_cert.pem из HSM для user_id=system, type=cert")
	certData, err := hsm.Retrieve("system", "cert", "/intermediate_cert.pem")
	if err != nil {
		log.Printf("Ошибка загрузки /intermediate_cert.pem: %v", err)
		return nil, nil, fmt.Errorf("не удалось извлечь /intermediate_cert.pem из HSM: %v", err)
	}
	certBlock, _ := pem.Decode(certData)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		log.Printf("Неверный формат сертификата в /intermediate_cert.pem")
		return nil, nil, fmt.Errorf("неверный формат сертификата в /intermediate_cert.pem")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		log.Printf("Ошибка парсинга сертификата: %v", err)
		return nil, nil, fmt.Errorf("ошибка парсинга сертификата: %v", err)
	}

	log.Printf("Успешно загружен промежуточный CA")
	return privKey, cert, nil
}

// Проверка промежуточного CA корневым CA
func verifyIntermediateCA(intermediateCert *x509.Certificate, rootCert *x509.Certificate) error {
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)

	opts := x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: time.Now(),
	}

	_, err := intermediateCert.Verify(opts)
	if err != nil {
		return fmt.Errorf("ошибка верификации промежуточного CA: %v", err)
	}
	return nil
}

func GenerateKey(w http.ResponseWriter, r *http.Request) {
	session, _ := utils.Store.Get(r, "alert-session")
	adminID := r.Context().Value("userID").(int)

	if r.Method == http.MethodPost {
		utils.LogAction(utils.DB, adminID, "generate_key_attempt", "Попытка генерации ключа")

		userID, err := strconv.Atoi(r.FormValue("user_id"))
		if err != nil {
			log.Printf("Неверный ID пользователя: %v", err)
			utils.LogAction(utils.DB, adminID, "error", fmt.Sprintf("Неверный ID пользователя: %v", err))
			session.Values["alert"] = "Неверный ID пользователя."
			session.Values["alertType"] = "danger"
			session.Save(r, w)
			http.Redirect(w, r, "/generate_key", http.StatusSeeOther)
			return
		}

		bank := r.FormValue("bank")
		if bank == "" {
			utils.LogAction(utils.DB, adminID, "error", "Название банка не указано")
			session.Values["alert"] = "Укажите название банка."
			session.Values["alertType"] = "danger"
			session.Save(r, w)
			http.Redirect(w, r, "/generate_key", http.StatusSeeOther)
			return
		}

		privateKey, publicKey, err := utils.GenerateKeyPair()
		if err != nil {
			log.Printf("Ошибка генерации ключей: %v", err)
			utils.LogAction(utils.DB, adminID, "error", fmt.Sprintf("Ошибка генерации ключей для пользователя ID %d, банк %s: %v", userID, bank, err))
			session.Values["alert"] = "Ошибка сервера при генерации ключей."
			session.Values["alertType"] = "danger"
			session.Save(r, w)
			http.Redirect(w, r, "/generate_key", http.StatusSeeOther)
			return
		}

		// Формируем уникальные пути с использованием bank
		publicKeyFile := fmt.Sprintf("/%s/public.pem", bank)
		privateKeyFile := fmt.Sprintf("/%s/private.pem", bank)
		certificateFile := fmt.Sprintf("/%s/certificate.pem", bank)

		publicKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(publicKey),
		})
		err = hsm.Store(strconv.Itoa(userID), "key", publicKeyFile, publicKeyPEM)
		if err != nil {
			log.Printf("Ошибка сохранения публичного ключа в HSM: %v", err)
			utils.LogAction(utils.DB, adminID, "error", fmt.Sprintf("Ошибка сохранения публичного ключа %s в HSM: %v", publicKeyFile, err))
			session.Values["alert"] = "Ошибка сервера при сохранении публичного ключа."
			session.Values["alertType"] = "danger"
			session.Save(r, w)
			http.Redirect(w, r, "/generate_key", http.StatusSeeOther)
			return
		}

		privateKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		})
		err = hsm.Store(strconv.Itoa(userID), "key", privateKeyFile, privateKeyPEM)
		if err != nil {
			log.Printf("Ошибка сохранения приватного ключа в HSM: %v", err)
			utils.LogAction(utils.DB, adminID, "error", fmt.Sprintf("Ошибка сохранения приватного ключа %s в HSM: %v", privateKeyFile, err))
			session.Values["alert"] = "Ошибка сервера при сохранении приватного ключа."
			session.Values["alertType"] = "danger"
			session.Save(r, w)
			http.Redirect(w, r, "/generate_key", http.StatusSeeOther)
			return
		}

		certPEM, err := generateUserCertificate(intermediatePrivateKey, intermediateCert, publicKey, bank)
		if err != nil {
			log.Printf("Ошибка генерации сертификата: %v", err)
			utils.LogAction(utils.DB, adminID, "error", fmt.Sprintf("Ошибка генерации сертификата для пользователя ID %d, банк %s: %v", userID, bank, err))
			session.Values["alert"] = "Ошибка сервера при генерации сертификата."
			session.Values["alertType"] = "danger"
			session.Save(r, w)
			http.Redirect(w, r, "/generate_key", http.StatusSeeOther)
			return
		}

		err = hsm.Store(strconv.Itoa(userID), "cert", certificateFile, certPEM)
		if err != nil {
			log.Printf("Ошибка сохранения сертификата в HSM: %v", err)
			utils.LogAction(utils.DB, adminID, "error", fmt.Sprintf("Ошибка сохранения сертификата %s в HSM: %v", certificateFile, err))
			session.Values["alert"] = "Ошибка сервера при сохранении сертификата."
			session.Values["alertType"] = "danger"
			session.Save(r, w)
			http.Redirect(w, r, "/generate_key", http.StatusSeeOther)
			return
		}

		_, err = utils.DB.Exec("INSERT INTO signatures (user_id, bank, public_key_path, private_key_path, certificate_path) VALUES (?, ?, ?, ?, ?)",
			userID, bank, publicKeyFile, privateKeyFile, certificateFile)
		if err != nil {
			log.Printf("Ошибка записи в БД: %v", err)
			utils.LogAction(utils.DB, adminID, "error", fmt.Sprintf("Ошибка записи данных ключа для пользователя ID %d, банк %s в БД: %v", userID, bank, err))
			session.Values["alert"] = "Ошибка сервера при сохранении данных о ключах."
			session.Values["alertType"] = "danger"
			session.Save(r, w)
			http.Redirect(w, r, "/generate_key", http.StatusSeeOther)
			return
		}

		utils.LogAction(utils.DB, adminID, "generate_key", fmt.Sprintf("Сгенерирован ключ для пользователя ID %d, банк: %s", userID, bank))
		session.Values["alert"] = "Ключи успешно сгенерированы."
		session.Values["alertType"] = "success"
		session.Save(r, w)
		http.Redirect(w, r, "/generate_key", http.StatusSeeOther)
		return
	}

	users, err := getUsersForKeyGeneration()
	if err != nil {
		log.Printf("Ошибка получения пользователей: %v", err)
		utils.LogAction(utils.DB, adminID, "error", fmt.Sprintf("Ошибка получения списка пользователей: %v", err))
		http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
		return
	}

	keys, err := getAllKeys()
	if err != nil {
		log.Printf("Ошибка получения ключей: %v", err)
		utils.LogAction(utils.DB, adminID, "error", fmt.Sprintf("Ошибка получения списка ключей: %v", err))
		http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
		return
	}

	alert, hasAlert := session.Values["alert"].(string)
	alertType, _ := session.Values["alertType"].(string)
	if hasAlert {
		delete(session.Values, "alert")
		delete(session.Values, "alertType")
		session.Save(r, w)
	}

	tmpl, err := template.ParseFiles("templates/generate_key.html")
	if err != nil {
		log.Printf("Ошибка парсинга шаблона: %v", err)
		utils.LogAction(utils.DB, adminID, "error", fmt.Sprintf("Ошибка парсинга шаблона generate_key.html: %v", err))
		http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
		return
	}

	data := struct {
		Users     []models.User
		Keys      []models.Key
		Alert     string
		AlertType string
		HasAlert  bool
	}{
		Users:     users,
		Keys:      keys,
		Alert:     alert,
		AlertType: alertType,
		HasAlert:  hasAlert,
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		log.Printf("Ошибка выполнения шаблона: %v", err)
		utils.LogAction(utils.DB, adminID, "error", fmt.Sprintf("Ошибка выполнения шаблона generate_key.html: %v", err))
		http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
		return
	}
}

func DeleteKey(w http.ResponseWriter, r *http.Request) {
	session, _ := utils.Store.Get(r, "alert-session")
	adminID := r.Context().Value("userID").(int)

	if r.Method == http.MethodPost {
		utils.LogAction(utils.DB, adminID, "delete_key_attempt", "Попытка удаления ключа")

		keyID, err := strconv.Atoi(r.FormValue("key_id"))
		if err != nil {
			log.Printf("Неверный ID ключа: %v", err)
			utils.LogAction(utils.DB, adminID, "error", fmt.Sprintf("Неверный ID ключа: %v", err))
			session.Values["alert"] = "Неверный ID ключа."
			session.Values["alertType"] = "danger"
			session.Save(r, w)
			http.Redirect(w, r, "/generate_key", http.StatusSeeOther)
			return
		}

		key, err := getKeyByID(keyID)
		if err != nil {
			log.Printf("Ключ не найден: %v", err)
			utils.LogAction(utils.DB, adminID, "error", fmt.Sprintf("Ключ ID %d не найден: %v", keyID, err))
			session.Values["alert"] = "Ключ не найден."
			session.Values["alertType"] = "danger"
			session.Save(r, w)
			http.Redirect(w, r, "/generate_key", http.StatusSeeOther)
			return
		}

		var count int
		err = utils.DB.QueryRow("SELECT COUNT(*) FROM signed_documents WHERE key_id = ?", keyID).Scan(&count)
		if err != nil {
			log.Printf("Ошибка проверки связанных подписей: %v", err)
			utils.LogAction(utils.DB, adminID, "error", fmt.Sprintf("Ошибка проверки связанных подписей для ключа ID %d: %v", keyID, err))
			session.Values["alert"] = "Ошибка сервера при проверке ключа."
			session.Values["alertType"] = "danger"
			session.Save(r, w)
			http.Redirect(w, r, "/generate_key", http.StatusSeeOther)
			return
		}
		if count > 0 {
			utils.LogAction(utils.DB, adminID, "error", fmt.Sprintf("Нельзя удалить ключ ID %d, так как он использовался для подписей", keyID))
			session.Values["alert"] = "Нельзя удалить ключ, так как он использовался для подписей."
			session.Values["alertType"] = "danger"
			session.Save(r, w)
			http.Redirect(w, r, "/generate_key", http.StatusSeeOther)
			return
		}

		_, err = utils.DB.Exec("DELETE FROM signatures WHERE id = ?", keyID)
		if err != nil {
			log.Printf("Ошибка удаления из БД: %v", err)
			utils.LogAction(utils.DB, adminID, "error", fmt.Sprintf("Ошибка удаления ключа ID %d из БД: %v", keyID, err))
			session.Values["alert"] = "Ошибка сервера при удалении данных о ключе."
			session.Values["alertType"] = "danger"
			session.Save(r, w)
			http.Redirect(w, r, "/generate_key", http.StatusSeeOther)
			return
		}

		for _, path := range []string{key.PublicKeyPath, key.PrivateKeyPath, key.CertificatePath} {
			fileType := "key"
			if path == key.CertificatePath {
				fileType = "cert"
			}
			err = hsm.Delete(strconv.Itoa(key.UserID), fileType, path)
			if err != nil {
				log.Printf("Ошибка удаления файла %s из HSM: %v", path, err)
				utils.LogAction(utils.DB, adminID, "error", fmt.Sprintf("Ошибка удаления файла %s из HSM: %v", path, err))
				session.Values["alert"] = "Ошибка сервера при удалении файлов ключа."
				session.Values["alertType"] = "danger"
				session.Save(r, w)
				http.Redirect(w, r, "/generate_key", http.StatusSeeOther)
				return
			}
		}

		utils.LogAction(utils.DB, adminID, "delete_key", fmt.Sprintf("Удалён ключ ID %d для пользователя ID %d", keyID, key.UserID))
		session.Values["alert"] = "Ключ успешно удалён."
		session.Values["alertType"] = "success"
		session.Save(r, w)
		http.Redirect(w, r, "/generate_key", http.StatusSeeOther)
		return
	}
}

func SearchKeys(w http.ResponseWriter, r *http.Request) {
	session, _ := utils.Store.Get(r, "alert-session")
	adminID := r.Context().Value("userID").(int)
	query := r.URL.Query().Get("query")

	utils.LogAction(utils.DB, adminID, "search_keys_attempt", fmt.Sprintf("Поиск ключей с запросом: %s", query))

	var keys []models.Key
	var err error

	if query == "" {
		keys, err = getAllKeys()
	} else {
		keys, err = searchKeys(query)
		if len(keys) == 0 {
			utils.LogAction(utils.DB, adminID, "search_keys", fmt.Sprintf("Ключи по запросу %s не найдены", query))
			session.Values["alert"] = "Ключи по запросу \"" + query + "\" не найдены."
			session.Values["alertType"] = "danger"
		}
	}

	if err != nil {
		log.Printf("Ошибка поиска ключей: %v", err)
		utils.LogAction(utils.DB, adminID, "error", fmt.Sprintf("Ошибка поиска ключей с запросом %s: %v", query, err))
		http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
		return
	}

	users, err := getUsersForKeyGeneration()
	if err != nil {
		log.Printf("Ошибка получения пользователей: %v", err)
		utils.LogAction(utils.DB, adminID, "error", fmt.Sprintf("Ошибка получения списка пользователей: %v", err))
		http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
		return
	}

	alert, hasAlert := session.Values["alert"].(string)
	alertType, _ := session.Values["alertType"].(string)
	if hasAlert {
		delete(session.Values, "alert")
		delete(session.Values, "alertType")
		session.Save(r, w)
	}

	tmpl, err := template.ParseFiles("templates/generate_key.html")
	if err != nil {
		log.Printf("Ошибка парсинга шаблона: %v", err)
		utils.LogAction(utils.DB, adminID, "error", fmt.Sprintf("Ошибка парсинга шаблона generate_key.html: %v", err))
		http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
		return
	}

	data := struct {
		Users     []models.User
		Keys      []models.Key
		Alert     string
		AlertType string
		HasAlert  bool
	}{
		Users:     users,
		Keys:      keys,
		Alert:     alert,
		AlertType: alertType,
		HasAlert:  hasAlert,
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		log.Printf("Ошибка выполнения шаблона: %v", err)
		utils.LogAction(utils.DB, adminID, "error", fmt.Sprintf("Ошибка выполнения шаблона generate_key.html: %v", err))
		http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
		return
	}
}

func ViewCertificate(w http.ResponseWriter, r *http.Request) {
	session, _ := utils.Store.Get(r, "alert-session")
	adminID := r.Context().Value("userID").(int)

	keyID, err := strconv.Atoi(r.URL.Query().Get("key_id"))
	if err != nil {
		log.Printf("Неверный ID ключа: %v", err)
		utils.LogAction(utils.DB, adminID, "error", fmt.Sprintf("Неверный ID ключа: %v", err))
		session.Values["alert"] = "Неверный ID ключа."
		session.Values["alertType"] = "danger"
		session.Save(r, w)
		http.Redirect(w, r, "/generate_key", http.StatusSeeOther)
		return
	}

	key, err := getKeyByID(keyID)
	if err != nil {
		log.Printf("Ключ не найден: %v", err)
		utils.LogAction(utils.DB, adminID, "error", fmt.Sprintf("Ключ ID %d не найден: %v", keyID, err))
		session.Values["alert"] = "Ключ не найден."
		session.Values["alertType"] = "danger"
		session.Save(r, w)
		http.Redirect(w, r, "/generate_key", http.StatusSeeOther)
		return
	}

	certData, err := hsm.Retrieve(strconv.Itoa(key.UserID), "cert", key.CertificatePath)
	if err != nil {
		log.Printf("Ошибка чтения сертификата из HSM: %v", err)
		utils.LogAction(utils.DB, adminID, "error", fmt.Sprintf("Ошибка чтения сертификата %s из HSM: %v", key.CertificatePath, err))
		session.Values["alert"] = "Ошибка чтения сертификата."
		session.Values["alertType"] = "danger"
		session.Save(r, w)
		http.Redirect(w, r, "/generate_key", http.StatusSeeOther)
		return
	}

	block, _ := pem.Decode(certData)
	if block == nil {
		log.Printf("Ошибка декодирования PEM")
		utils.LogAction(utils.DB, adminID, "error", "Ошибка декодирования PEM сертификата")
		session.Values["alert"] = "Ошибка декодирования сертификата."
		session.Values["alertType"] = "danger"
		session.Save(r, w)
		http.Redirect(w, r, "/generate_key", http.StatusSeeOther)
		return
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Printf("Ошибка парсинга сертификата: %v", err)
		utils.LogAction(utils.DB, adminID, "error", fmt.Sprintf("Ошибка парсинга сертификата: %v", err))
		session.Values["alert"] = "Ошибка парсинга сертификата."
		session.Values["alertType"] = "danger"
		session.Save(r, w)
		http.Redirect(w, r, "/generate_key", http.StatusSeeOther)
		return
	}

	// Проверка подлинности сертификата
	err = verifyCertificate(cert, intermediateCert, rootCert)
	if err != nil {
		log.Printf("Сертификат недействителен: %v", err)
		utils.LogAction(utils.DB, adminID, "error", fmt.Sprintf("Сертификат для ключа ID %d недействителен: %v", keyID, err))
		session.Values["alert"] = fmt.Sprintf("Сертификат недействителен: %v", err)
		session.Values["alertType"] = "danger"
		session.Save(r, w)
		http.Redirect(w, r, "/generate_key", http.StatusSeeOther)
		return
	}

	// Преобразуем срез Organization в строку
	organization := strings.Join(cert.Subject.Organization, ", ")

	tmpl, err := template.ParseFiles("templates/view_certificate.html")
	if err != nil {
		log.Printf("Ошибка парсинга шаблона: %v", err)
		utils.LogAction(utils.DB, adminID, "error", fmt.Sprintf("Ошибка парсинга шаблона view_certificate.html: %v", err))
		http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
		return
	}

	data := struct {
		Key          models.Key
		Certificate  *x509.Certificate
		Organization string
	}{
		Key:          key,
		Certificate:  cert,
		Organization: organization,
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		log.Printf("Ошибка выполнения шаблона: %v", err)
		utils.LogAction(utils.DB, adminID, "error", fmt.Sprintf("Ошибка выполнения шаблона view_certificate.html: %v", err))
		http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
		return
	}
}

func getAllKeys() ([]models.Key, error) {
	rows, err := utils.DB.Query("SELECT s.id, s.user_id, u.login, s.bank, s.public_key_path, s.private_key_path, s.certificate_path FROM signatures s JOIN users u ON s.user_id = u.id")
	if err != nil {
		utils.LogAction(utils.DB, 0, "error", fmt.Sprintf("Ошибка запроса всех ключей: %v", err))
		return nil, err
	}
	defer rows.Close()

	var keys []models.Key
	for rows.Next() {
		var key models.Key
		err := rows.Scan(&key.ID, &key.UserID, &key.UserName, &key.Bank, &key.PublicKeyPath, &key.PrivateKeyPath, &key.CertificatePath)
		if err != nil {
			utils.LogAction(utils.DB, 0, "error", fmt.Sprintf("Ошибка чтения ключей: %v", err))
			return nil, err
		}

		certData, err := hsm.Retrieve(strconv.Itoa(key.UserID), "cert", key.CertificatePath)
		if err == nil {
			block, _ := pem.Decode(certData)
			if block != nil {
				cert, err := x509.ParseCertificate(block.Bytes)
				if err == nil {
					key.NotBefore = cert.NotBefore
					key.NotAfter = cert.NotAfter
				}
			}
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
		utils.LogAction(utils.DB, 0, "error", fmt.Sprintf("Ошибка получения ключа ID %d: %v", keyID, err))
		return key, err
	}

	certData, err := hsm.Retrieve(strconv.Itoa(key.UserID), "cert", key.CertificatePath)
	if err == nil {
		block, _ := pem.Decode(certData)
		if block != nil {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				key.NotBefore = cert.NotBefore
				key.NotAfter = cert.NotAfter
			}
		}
	}
	return key, nil
}

func getUsersForKeyGeneration() ([]models.User, error) {
	rows, err := utils.DB.Query("SELECT id, login FROM users")
	if err != nil {
		utils.LogAction(utils.DB, 0, "error", fmt.Sprintf("Ошибка запроса пользователей: %v", err))
		return nil, err
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var user models.User
		err := rows.Scan(&user.ID, &user.Login)
		if err != nil {
			utils.LogAction(utils.DB, 0, "error", fmt.Sprintf("Ошибка чтения пользователей: %v", err))
			return nil, err
		}
		users = append(users, user)
	}

	return users, nil
}

func searchKeys(query string) ([]models.Key, error) {
	rows, err := utils.DB.Query("SELECT s.id, s.user_id, u.login, s.bank, s.public_key_path, s.private_key_path, s.certificate_path FROM signatures s JOIN users u ON s.user_id = u.id WHERE u.login LIKE ? OR s.bank LIKE ?", "%"+query+"%", "%"+query+"%")
	if err != nil {
		utils.LogAction(utils.DB, 0, "error", fmt.Sprintf("Ошибка поиска ключей по запросу %s: %v", query, err))
		return nil, err
	}
	defer rows.Close()

	var keys []models.Key
	for rows.Next() {
		var key models.Key
		err := rows.Scan(&key.ID, &key.UserID, &key.UserName, &key.Bank, &key.PublicKeyPath, &key.PrivateKeyPath, &key.CertificatePath)
		if err != nil {
			utils.LogAction(utils.DB, 0, "error", fmt.Sprintf("Ошибка чтения результатов поиска ключей: %v", err))
			return nil, err
		}

		certData, err := hsm.Retrieve(strconv.Itoa(key.UserID), "cert", key.CertificatePath)
		if err == nil {
			block, _ := pem.Decode(certData)
			if block != nil {
				cert, err := x509.ParseCertificate(block.Bytes)
				if err == nil {
					key.NotBefore = cert.NotBefore
					key.NotAfter = cert.NotAfter
				}
			}
		}
		keys = append(keys, key)
	}

	return keys, nil
}

func generateRootCA() (*rsa.PrivateKey, *x509.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("ошибка генерации ключа: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Root CA"},
			CommonName:   "Root CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("ошибка создания сертификата: %v", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("ошибка парсинга сертификата: %v", err)
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	err = hsm.Store("system", "key", "/root_key.pem", privateKeyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("ошибка сохранения root_key.pem в HSM: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})
	err = hsm.Store("system", "cert", "/root_cert.pem", certPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("ошибка сохранения root_cert.pem в HSM: %v", err)
	}

	return privateKey, cert, nil
}

func generateIntermediateCA(rootPrivateKey *rsa.PrivateKey, rootCert *x509.Certificate) (*rsa.PrivateKey, *x509.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("ошибка генерации ключа: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Intermediate CA"},
			CommonName:   "Intermediate CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, rootCert, &privateKey.PublicKey, rootPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("ошибка создания сертификата: %v", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("ошибка парсинга сертификата: %v", err)
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	err = hsm.Store("system", "key", "/intermediate_key.pem", privateKeyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("ошибка сохранения intermediate_key.pem в HSM: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})
	err = hsm.Store("system", "cert", "/intermediate_cert.pem", certPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("ошибка сохранения intermediate_cert.pem в HSM: %v", err)
	}

	return privateKey, cert, nil
}

func generateUserCertificate(intermediatePrivateKey *rsa.PrivateKey, intermediateCert *x509.Certificate, userPublicKey *rsa.PublicKey, bank string) ([]byte, error) {
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{bank},
			CommonName:   bank,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, intermediateCert, userPublicKey, intermediatePrivateKey)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания сертификата: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	return certPEM, nil
}

func verifyCertificate(cert *x509.Certificate, intermediateCert *x509.Certificate, rootCert *x509.Certificate) error {
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)

	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediateCert)

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   time.Now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	_, err := cert.Verify(opts)
	if err != nil {
		return fmt.Errorf("ошибка верификации сертификата: %v", err)
	}

	now := time.Now()
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("сертификат еще не действителен")
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("срок действия сертификата истек")
	}

	return nil
}
