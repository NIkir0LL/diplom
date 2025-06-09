package handlers

import (
	"archive/zip"
	"bytes"
	"fmt"
	"html/template"
	"io"
	"log"
	"myproject/models"
	"myproject/utils"
	"net/http"
	"strings"
)

func UploadVerifyArchive(w http.ResponseWriter, r *http.Request) {
	// Получение userID из контекста
	userID, ok := r.Context().Value("userID").(int)
	if !ok || userID == 0 {
		userID = -1
		utils.LogAction(utils.DB, userID, "error", "Неавторизованный доступ к проверке архива")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Инициализация сессии для уведомлений
	session, _ := utils.Store.Get(r, "alert-session")

	if r.Method == http.MethodPost {
		utils.LogAction(utils.DB, userID, "upload_verify_archive_attempt", fmt.Sprintf("Попытка проверки архива пользователем userID=%d", userID))

		// Получение загруженного архива
		file, _, err := r.FormFile("archive")
		if err != nil {
			log.Printf("Ошибка получения архива: %v", err)
			session.Values["alert"] = "Ошибка загрузки архива."
			session.Values["alertType"] = "danger"
			session.Save(r, w)
			http.Redirect(w, r, "/upload_verify_archive", http.StatusSeeOther)
			return
		}
		defer file.Close()

		// Чтение данных архива
		fileData, err := io.ReadAll(file)
		if err != nil {
			log.Printf("Ошибка чтения архива: %v", err)
			session.Values["alert"] = "Ошибка чтения архива."
			session.Values["alertType"] = "danger"
			session.Save(r, w)
			http.Redirect(w, r, "/upload_verify_archive", http.StatusSeeOther)
			return
		}

		// Открытие ZIP-архива
		zipReader, err := zip.NewReader(bytes.NewReader(fileData), int64(len(fileData)))
		if err != nil {
			log.Printf("Ошибка открытия ZIP: %v", err)
			session.Values["alert"] = "Неверный формат архива."
			session.Values["alertType"] = "danger"
			session.Save(r, w)
			http.Redirect(w, r, "/upload_verify_archive", http.StatusSeeOther)
			return
		}

		// Извлечение файлов из архива
		files := make(map[string][]byte)
		var publicKeyName, certName, signatureName string
		for _, f := range zipReader.File {
			rc, err := f.Open()
			if err != nil {
				log.Printf("Ошибка открытия файла в ZIP: %v", err)
				continue
			}
			data, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				log.Printf("Ошибка чтения файла в ZIP: %v", err)
				continue
			}
			files[f.Name] = data
			log.Printf("Найден файл в архиве: %s", f.Name)

			// Определение типов файлов
			if strings.HasSuffix(f.Name, ".pem") && strings.Contains(strings.ToLower(f.Name), "public") {
				publicKeyName = f.Name
			} else if f.Name == "certificate.pem" {
				certName = f.Name
			} else if strings.HasSuffix(f.Name, ".sig") {
				signatureName = f.Name
			}
		}

		// Проверка наличия всех необходимых файлов
		if publicKeyName == "" || certName == "" || signatureName == "" {
			log.Printf("Отсутствуют файлы в архиве: publicKeyName=%s, certName=%s, signatureName=%s", publicKeyName, certName, signatureName)
			session.Values["alert"] = "Архив не содержит необходимых файлов (публичный ключ, сертификат или подпись)."
			session.Values["alertType"] = "danger"
			session.Save(r, w)
			http.Redirect(w, r, "/upload_verify_archive", http.StatusSeeOther)
			return
		}

		// Определение имени подписанного файла
		var signedFileName string
		for name := range files {
			if name != publicKeyName && name != certName && name != signatureName {
				signedFileName = name
				break
			}
		}
		if signedFileName == "" {
			log.Printf("Архив не содержит подписанного файла")
			session.Values["alert"] = "Архив не содержит подписанного файла."
			session.Values["alertType"] = "danger"
			session.Save(r, w)
			http.Redirect(w, r, "/upload_verify_archive", http.StatusSeeOther)
			return
		}
		signedFileData := files[signedFileName]
		log.Printf("Извлечен подписанный файл: %s", signedFileName)

		// Проверка подписи и документа
		signedDoc, err := models.FindSignedDocumentByKeyAndCert(utils.DB, files[publicKeyName], files[certName], files[signatureName], signedFileData)
		if err != nil {
			log.Printf("Ошибка поиска документа: %v", err)
			session.Values["alert"] = "Ошибка проверки подписи."
			session.Values["alertType"] = "danger"
			session.Save(r, w)
			http.Redirect(w, r, "/upload_verify_archive", http.StatusSeeOther)
			return
		}
		if signedDoc == nil {
			log.Printf("Документ не найден в системе")
			session.Values["alert"] = "Подпись не найдена, недействительна или сертификат не принадлежит системе."
			session.Values["alertType"] = "danger"
			session.Save(r, w)
			http.Redirect(w, r, "/upload_verify_archive", http.StatusSeeOther)
			return
		}

		// Успешная проверка
		log.Printf("Подпись и сертификат успешно проверены для документа ID=%d, Filename=%s", signedDoc.ID, signedDoc.Filename)
		session.Values["alert"] = "Подпись успешно проверена и подтверждена."
		session.Values["alertType"] = "success"
		session.Save(r, w)
		http.Redirect(w, r, "/upload_verify_archive", http.StatusSeeOther)
		return
	}

	// Обработка GET-запроса: отображение формы
	tmpl, err := template.ParseFiles("templates/upload_verify_archive.html")
	if err != nil {
		log.Printf("Ошибка парсинга шаблона: %v", err)
		http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
		return
	}

	// Обработка уведомлений
	alert, hasAlert := session.Values["alert"].(string)
	alertType, _ := session.Values["alertType"].(string)
	if hasAlert {
		delete(session.Values, "alert")
		delete(session.Values, "alertType")
		session.Save(r, w)
	}

	data := struct {
		Alert     string
		AlertType string
		HasAlert  bool
	}{
		Alert:     alert,
		AlertType: alertType,
		HasAlert:  hasAlert,
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		log.Printf("Ошибка выполнения шаблона: %v", err)
		http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
		return
	}
}
