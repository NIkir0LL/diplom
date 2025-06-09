package handlers

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"log"
	"myproject/hsm"
	"myproject/utils"
	"net/http"
	"path/filepath"
	"strconv"
)

func DownloadSignedArchive(w http.ResponseWriter, r *http.Request) {
	userID, ok := r.Context().Value("userID").(int)
	if !ok || userID == 0 {
		userID = -1
		utils.LogAction(utils.DB, userID, "error", "Неавторизованный доступ к выгрузке архива")
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	role := r.Context().Value("role").(string)
	session, _ := utils.Store.Get(r, "alert-session")

	fileIDStr := r.URL.Query().Get("file_id")
	keyIDStr := r.URL.Query().Get("key_id")

	fileID, err := strconv.Atoi(fileIDStr)
	if err != nil {
		log.Printf("Неверный ID файла: %v", err)
		utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Неверный ID файла: %v", err))
		session.Values["alert"] = "Неверный ID файла."
		session.Values["alertType"] = "danger"
		session.Save(r, w)
		http.Redirect(w, r, "/verify_document", http.StatusSeeOther)
		return
	}

	keyID, err := strconv.Atoi(keyIDStr)
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
		log.Printf("Документ не найден: %v", err)
		utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Документ не найден: %v", err))
		session.Values["alert"] = "Документ не найден."
		session.Values["alertType"] = "danger"
		session.Save(r, w)
		http.Redirect(w, r, "/verify_document", http.StatusSeeOther)
		return
	}

	signature, err := getSignature(keyID)
	if err != nil {
		log.Printf("Ключ не найден: %v", err)
		utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Ключ не найден: %v", err))
		session.Values["alert"] = "Ключ не найден."
		session.Values["alertType"] = "danger"
		session.Save(r, w)
		http.Redirect(w, r, "/verify_document", http.StatusSeeOther)
		return
	}

	if role != "admin" && signature.UserID != userID {
		log.Printf("Попытка скачать чужой документ: userID %d, keyID %d", userID, keyID)
		utils.LogAction(utils.DB, userID, "error", fmt.Sprintf("Попытка скачать чужой документ: userID %d, keyID %d", userID, keyID))
		session.Values["alert"] = "У вас нет прав для скачивания этого документа."
		session.Values["alertType"] = "danger"
		session.Save(r, w)
		http.Redirect(w, r, "/verify_document", http.StatusSeeOther)
		return
	}

	// Извлечение файлов из HSM
	signedFileData, err := hsm.Retrieve(strconv.Itoa(signature.UserID), "file", signedDoc.SignedFilePath)
	if err != nil {
		log.Printf("Ошибка загрузки подписанного файла: %v", err)
		session.Values["alert"] = "Ошибка загрузки подписанного файла."
		session.Values["alertType"] = "danger"
		session.Save(r, w)
		http.Redirect(w, r, "/verify_document", http.StatusSeeOther)
		return
	}

	publicKeyData, err := hsm.Retrieve(strconv.Itoa(signature.UserID), "key", signedDoc.PublicKeyPath)
	if err != nil {
		log.Printf("Ошибка загрузки публичного ключа: %v", err)
		session.Values["alert"] = "Ошибка загрузки публичного ключа."
		session.Values["alertType"] = "danger"
		session.Save(r, w)
		http.Redirect(w, r, "/verify_document", http.StatusSeeOther)
		return
	}

	signatureData, err := hsm.Retrieve(strconv.Itoa(signature.UserID), "signature", signedDoc.SignaturePath)
	if err != nil {
		log.Printf("Ошибка загрузки подписи: %v", err)
		session.Values["alert"] = "Ошибка загрузки подписи."
		session.Values["alertType"] = "danger"
		session.Save(r, w)
		http.Redirect(w, r, "/verify_document", http.StatusSeeOther)
		return
	}

	certData, err := hsm.Retrieve(strconv.Itoa(signature.UserID), "cert", signedDoc.CertificatePath)
	if err != nil {
		log.Printf("Ошибка загрузки сертификата: %v", err)
		session.Values["alert"] = "Ошибка загрузки сертификата."
		session.Values["alertType"] = "danger"
		session.Save(r, w)
		http.Redirect(w, r, "/verify_document", http.StatusSeeOther)
		return
	}

	// Создание ZIP-архива
	buf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(buf)

	files := []struct {
		Name string
		Data []byte
	}{
		{filepath.Base(signedDoc.SignedFilePath), signedFileData},
		{filepath.Base(signedDoc.PublicKeyPath), publicKeyData},
		{filepath.Base(signedDoc.SignaturePath), signatureData},
		{filepath.Base(signedDoc.CertificatePath), certData},
	}

	for _, file := range files {
		f, err := zipWriter.Create(file.Name)
		if err != nil {
			log.Printf("Ошибка создания файла в архиве: %v", err)
			session.Values["alert"] = "Ошибка создания архива."
			session.Values["alertType"] = "danger"
			session.Save(r, w)
			http.Redirect(w, r, "/verify_document", http.StatusSeeOther)
			return
		}
		_, err = f.Write(file.Data)
		if err != nil {
			log.Printf("Ошибка записи файла в архив: %v", err)
			session.Values["alert"] = "Ошибка создания архива."
			session.Values["alertType"] = "danger"
			session.Save(r, w)
			http.Redirect(w, r, "/verify_document", http.StatusSeeOther)
			return
		}
	}

	err = zipWriter.Close()
	if err != nil {
		log.Printf("Ошибка закрытия архива: %v", err)
		session.Values["alert"] = "Ошибка создания архива."
		session.Values["alertType"] = "danger"
		session.Save(r, w)
		http.Redirect(w, r, "/verify_document", http.StatusSeeOther)
		return
	}

	// Отправка архива
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"signed_archive_%d_%d.zip\"", fileID, keyID))
	_, err = io.Copy(w, buf)
	if err != nil {
		log.Printf("Ошибка отправки архива: %v", err)
		return
	}

	utils.LogAction(utils.DB, userID, "download_signed_archive_success", fmt.Sprintf("Архив успешно скачан: fileID=%d, keyID=%d", fileID, keyID))
}
