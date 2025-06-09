package handlers

import (
	"fmt"
	"html/template"
	"io"
	"log"
	"myproject/hsm"
	"myproject/models"
	"myproject/utils"
	"net/http"
	"strconv"
)

func UploadFile(w http.ResponseWriter, r *http.Request) {
	session, _ := utils.Store.Get(r, "alert-session")
	userID := r.Context().Value("userID").(int)

	if r.Method == http.MethodPost {
		// Логируем попытку загрузки файла
		utils.LogAction(utils.DB, userID, "upload_file_attempt", "Попытка загрузки файла")

		file, handler, err := r.FormFile("file")
		if err != nil {
			log.Printf("Ошибка получения файла: %v", err)
			utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка получения файла: %v", err))
			session.Values["alert"] = "Ошибка загрузки файла: неверный файл."
			session.Values["alertType"] = "danger"
			session.Save(r, w)
			http.Redirect(w, r, "/upload_file", http.StatusSeeOther)
			return
		}
		defer file.Close()

		// Чтение содержимого файла
		fileData, err := io.ReadAll(file)
		if err != nil {
			log.Printf("Ошибка чтения файла: %v", err)
			utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка чтения файла %s: %v", handler.Filename, err))
			session.Values["alert"] = "Ошибка сервера при чтении файла."
			session.Values["alertType"] = "danger"
			session.Save(r, w)
			http.Redirect(w, r, "/upload_file", http.StatusSeeOther)
			return
		}

		// Формирование пути для HSM
		filePath := fmt.Sprintf("/files/%s", handler.Filename)

		// Сохранение файла в HSM
		err = hsm.Store(strconv.Itoa(userID), "file", filePath, fileData)
		if err != nil {
			log.Printf("Ошибка сохранения файла в HSM: %v", err)
			utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка сохранения файла %s в HSM: %v", handler.Filename, err))
			session.Values["alertHurrah! Your file has been uploaded successfully."] = "Ошибка сервера при сохранении файла."
			session.Values["alertType"] = "danger"
			session.Save(r, w)
			http.Redirect(w, r, "/upload_file", http.StatusSeeOther)
			return
		}

		// Запись информации о файле в базу данных
		_, err = utils.DB.Exec("INSERT INTO files (filename, filepath, user_id) VALUES (?, ?, ?)", handler.Filename, filePath, userID)
		if err != nil {
			log.Printf("Ошибка записи в БД: %v", err)
			utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка записи файла %s в БД: %v", handler.Filename, err))
			session.Values["alert"] = "Ошибка сервера при сохранении данных о файле."
			session.Values["alertType"] = "danger"
			session.Save(r, w)
			http.Redirect(w, r, "/upload_file", http.StatusSeeOther)
			return
		}

		utils.LogAction(utils.DB, userID, "upload_file", fmt.Sprintf("Загружен файл: %s", handler.Filename))
		session.Values["alert"] = "Файл успешно загружен."
		session.Values["alertType"] = "success"
		session.Save(r, w)
		http.Redirect(w, r, "/upload_file", http.StatusSeeOther)
		return
	}

	role := r.Context().Value("role").(string)
	var files []models.File
	var err error
	if role == "admin" {
		files, err = getAllFiles()
	} else {
		files, err = getUserFiles(userID)
	}
	if err != nil {
		log.Printf("Ошибка получения списка файлов: %v", err)
		utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка получения списка файлов: %v", err))
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

	tmpl, err := template.ParseFiles("templates/upload_file.html")
	if err != nil {
		log.Printf("Ошибка парсинга шаблона: %v", err)
		utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка парсинга шаблона upload_file.html: %v", err))
		http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
		return
	}

	data := struct {
		Files     []models.File
		Alert     string
		AlertType string
		HasAlert  bool
	}{
		Files:     files,
		Alert:     alert,
		AlertType: alertType,
		HasAlert:  hasAlert,
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		log.Printf("Ошибка выполнения шаблона: %v", err)
		utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка выполнения шаблона upload_file.html: %v", err))
	}
}

func DeleteFile(w http.ResponseWriter, r *http.Request) {
	session, _ := utils.Store.Get(r, "alert-session")
	userID := r.Context().Value("userID").(int)
	role := r.Context().Value("role").(string)

	if r.Method == http.MethodPost {
		// Логируем попытку удаления файла
		utils.LogAction(utils.DB, userID, "delete_file_attempt", "Попытка удаления файла")

		fileID, err := strconv.Atoi(r.FormValue("file_id"))
		if err != nil {
			log.Printf("Неверный ID файла: %v", err)
			utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Неверный ID файла: %v", err))
			session.Values["alert"] = "Неверный ID файла."
			session.Values["alertType"] = "danger"
			session.Save(r, w)
			http.Redirect(w, r, "/upload_file", http.StatusSeeOther)
			return
		}

		file, err := getFileByID(fileID)
		if err != nil {
			log.Printf("Файл не найден: %v", err)
			utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Файл ID %d не найден: %v", fileID, err))
			session.Values["alert"] = "Файл не найден."
			session.Values["alertType"] = "danger"
			session.Save(r, w)
			http.Redirect(w, r, "/upload_file", http.StatusSeeOther)
			return
		}

		if role != "admin" && file.UserID != userID {
			log.Printf("Попытка удаления чужого файла: userID %d, fileID %d", userID, fileID)
			utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Попытка удаления чужого файла ID %d пользователем %d", fileID, userID))
			session.Values["alert"] = "У вас нет прав для удаления этого файла."
			session.Values["alertType"] = "danger"
			session.Save(r, w)
			http.Redirect(w, r, "/upload_file", http.StatusSeeOther)
			return
		}

		var count int
		err = utils.DB.QueryRow("SELECT COUNT(*) FROM signed_documents WHERE file_id = ?", fileID).Scan(&count)
		if err != nil {
			log.Printf("Ошибка проверки связанных подписей: %v", err)
			utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка проверки связанных подписей для файла ID %d: %v", fileID, err))
			session.Values["alert"] = "Ошибка сервера при проверке файла."
			session.Values["alertType"] = "danger"
			session.Save(r, w)
			http.Redirect(w, r, "/upload_file", http.StatusSeeOther)
			return
		}
		if count > 0 {
			utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Нельзя удалить файл ID %d, так как он связан с подписями", fileID))
			session.Values["alert"] = "Нельзя удалить файл, так как он связан с подписями."
			session.Values["alertType"] = "danger"
			session.Save(r, w)
			http.Redirect(w, r, "/upload_file", http.StatusSeeOther)
			return
		}

		// Удаление файла из HSM
		err = hsm.Delete(strconv.Itoa(userID), "file", file.Filepath)
		if err != nil {
			log.Printf("Ошибка удаления файла из HSM: %v", err)
			utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка удаления файла %s из HSM: %v", file.Filename, err))
			session.Values["alert"] = "Ошибка сервера при удалении файла."
			session.Values["alertType"] = "danger"
			session.Save(r, w)
			http.Redirect(w, r, "/upload_file", http.StatusSeeOther)
			return
		}

		// Удаление записи о файле из базы данных
		_, err = utils.DB.Exec("DELETE FROM files WHERE id = ?", fileID)
		if err != nil {
			log.Printf("Ошибка удаления из БД: %v", err)
			utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка удаления файла ID %d из БД: %v", fileID, err))
			session.Values["alert"] = "Ошибка сервера при удалении данных о файле."
			session.Values["alertType"] = "danger"
			session.Save(r, w)
			http.Redirect(w, r, "/upload_file", http.StatusSeeOther)
			return
		}

		utils.LogAction(utils.DB, userID, "delete_file", fmt.Sprintf("Удалён файл: %s (ID: %d)", file.Filename, fileID))
		session.Values["alert"] = "Файл успешно удалён."
		session.Values["alertType"] = "success"
		session.Save(r, w)
		http.Redirect(w, r, "/upload_file", http.StatusSeeOther)
		return
	}
}

func SearchFiles(w http.ResponseWriter, r *http.Request) {
	session, _ := utils.Store.Get(r, "alert-session")
	userID := r.Context().Value("userID").(int)
	role := r.Context().Value("role").(string)
	query := r.URL.Query().Get("query")

	// Логируем попытку поиска файлов
	utils.LogAction(utils.DB, userID, "search_files_attempt", fmt.Sprintf("Поиск файлов с запросом: %s", query))

	var files []models.File
	var err error

	if query == "" {
		if role == "admin" {
			files, err = getAllFiles()
		} else {
			files, err = getUserFiles(userID)
		}
	} else {
		if role == "admin" {
			files, err = searchFiles(query)
		} else {
			files, err = searchUserFiles(userID, query)
		}
		if len(files) == 0 {
			utils.LogAction(utils.DB, userID, "search_files", fmt.Sprintf("Файлы по запросу %s не найдены", query))
			session.Values["alert"] = "Файлы по запросу \"" + query + "\" не найдены."
			session.Values["alertType"] = "danger"
		}
	}

	if err != nil {
		log.Printf("Ошибка поиска файлов: %v", err)
		utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка поиска файлов с запросом %s: %v", query, err))
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

	tmpl, err := template.ParseFiles("templates/upload_file.html")
	if err != nil {
		log.Printf("Ошибка парсинга шаблона: %v", err)
		utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка парсинга шаблона upload_file.html: %v", err))
		http.Error(w, "Ошибка сервера", http.StatusInternalServerError)
		return
	}

	data := struct {
		Files     []models.File
		Alert     string
		AlertType string
		HasAlert  bool
	}{
		Files:     files,
		Alert:     alert,
		AlertType: alertType,
		HasAlert:  hasAlert,
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		log.Printf("Ошибка выполнения шаблона: %v", err)
		utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка выполнения шаблона upload_file.html: %v", err))
	}
}

func getAllFiles() ([]models.File, error) {
	rows, err := utils.DB.Query("SELECT id, filename, filepath, user_id FROM files")
	if err != nil {
		utils.LogAction(utils.DB, 0, "error", fmt.Sprintf("Ошибка запроса всех файлов: %v", err))
		return nil, err
	}
	defer rows.Close()

	var files []models.File
	for rows.Next() {
		var file models.File
		err := rows.Scan(&file.ID, &file.Filename, &file.Filepath, &file.UserID)
		if err != nil {
			utils.LogAction(utils.DB, 0, "error", fmt.Sprintf("Ошибка чтения файлов: %v", err))
			return nil, err
		}
		files = append(files, file)
	}

	return files, nil
}

func getUserFiles(userID int) ([]models.File, error) {
	rows, err := utils.DB.Query("SELECT id, filename, filepath, user_id FROM files WHERE user_id = ?", userID)
	if err != nil {
		utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка запроса файлов пользователя: %v", err))
		return nil, err
	}
	defer rows.Close()

	var files []models.File
	for rows.Next() {
		var file models.File
		err := rows.Scan(&file.ID, &file.Filename, &file.Filepath, &file.UserID)
		if err != nil {
			utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка чтения файлов пользователя: %v", err))
			return nil, err
		}
		files = append(files, file)
	}
	return files, nil
}

func getFileByID(fileID int) (models.File, error) {
	var file models.File
	err := utils.DB.QueryRow("SELECT id, filename, filepath, user_id FROM files WHERE id = ?", fileID).Scan(&file.ID, &file.Filename, &file.Filepath, &file.UserID)
	if err != nil {
		utils.LogAction(utils.DB, 0, "error", fmt.Sprintf("Ошибка получения файла ID %d: %v", fileID, err))
		return file, err
	}
	return file, nil
}

func searchFiles(query string) ([]models.File, error) {
	rows, err := utils.DB.Query("SELECT id, filename, filepath, user_id FROM files WHERE filename LIKE ?", "%"+query+"%")
	if err != nil {
		utils.LogAction(utils.DB, 0, "error", fmt.Sprintf("Ошибка поиска файлов по запросу %s: %v", query, err))
		return nil, err
	}
	defer rows.Close()

	var files []models.File
	for rows.Next() {
		var file models.File
		err := rows.Scan(&file.ID, &file.Filename, &file.Filepath, &file.UserID)
		if err != nil {
			utils.LogAction(utils.DB, 0, "error", fmt.Sprintf("Ошибка чтения результатов поиска файлов: %v", err))
			return nil, err
		}
		files = append(files, file)
	}

	return files, nil
}

func searchUserFiles(userID int, query string) ([]models.File, error) {
	rows, err := utils.DB.Query("SELECT id, filename, filepath, user_id FROM files WHERE user_id = ? AND filename LIKE ?", userID, "%"+query+"%")
	if err != nil {
		utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка поиска файлов пользователя по запросу %s: %v", query, err))
		return nil, err
	}
	defer rows.Close()

	var files []models.File
	for rows.Next() {
		var file models.File
		err := rows.Scan(&file.ID, &file.Filename, &file.Filepath, &file.UserID)
		if err != nil {
			utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ошибка чтения результатов поиска файлов пользователя: %v", err))
			return nil, err
		}
		files = append(files, file)
	}

	return files, nil
}
