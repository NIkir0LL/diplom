package hsm

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
)

// HSM_URL - базовый URL HSM сервера
const HSM_URL = "http://IP:8080"

// Store сохраняет данные в HSM через API
func Store(userID, fileType, filePath string, data []byte) error {
	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile("data", "data")
	if err != nil {
		return fmt.Errorf("ошибка создания формы: %v", err)
	}
	_, err = part.Write(data)
	if err != nil {
		return fmt.Errorf("ошибка записи данных в форму: %v", err)
	}

	_ = writer.WriteField("user_id", userID)
	_ = writer.WriteField("type", fileType)
	_ = writer.WriteField("path", filePath)

	err = writer.Close()
	if err != nil {
		return fmt.Errorf("ошибка закрытия формы: %v", err)
	}

	req, err := http.NewRequest("POST", HSM_URL+"/store", body)
	if err != nil {
		return fmt.Errorf("ошибка создания запроса: %v", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("ошибка выполнения запроса: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HSM вернул ошибку: %d, тело ответа: %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

// Retrieve извлекает данные из HSM через API
func Retrieve(userID, fileType, filePath string) ([]byte, error) {
	params := url.Values{}
	params.Add("user_id", userID)
	params.Add("type", fileType)
	params.Add("path", filePath)

	fullURL := HSM_URL + "/retrieve?" + params.Encode()

	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания запроса: %v", err)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ошибка выполнения запроса: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HSM вернул ошибку: %d, тело ответа: %s", resp.StatusCode, string(bodyBytes))
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("ошибка чтения ответа: %v", err)
	}

	return data, nil
}

// Sign подписывает данные с использованием ключа в HSM через API
func Sign(userID, fileType, keyPath, publicKeyPath string, data []byte) ([]byte, error) {
	body := new(bytes.Buffer)
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile("data", "data")
	if err != nil {
		return nil, fmt.Errorf("ошибка создания формы: %v", err)
	}
	_, err = part.Write(data)
	if err != nil {
		return nil, fmt.Errorf("ошибка записи данных в форму: %v", err)
	}

	_ = writer.WriteField("user_id", userID)
	_ = writer.WriteField("type", fileType)
	_ = writer.WriteField("key_path", keyPath)
	_ = writer.WriteField("public_key_path", publicKeyPath)

	err = writer.Close()
	if err != nil {
		return nil, fmt.Errorf("ошибка закрытия формы: %v", err)
	}

	req, err := http.NewRequest("POST", HSM_URL+"/sign", body)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания запроса: %v", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ошибка выполнения запроса: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HSM вернул ошибку: %d, тело ответа: %s", resp.StatusCode, string(bodyBytes))
	}

	signature, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("ошибка чтения подписи: %v", err)
	}

	return signature, nil
}

// Delete удаляет данные из HSM через API
func Delete(userID, fileType, filePath string) error {
	params := url.Values{}
	params.Add("user_id", userID)
	params.Add("type", fileType)
	params.Add("path", filePath)

	fullURL := HSM_URL + "/delete?" + params.Encode()

	req, err := http.NewRequest("DELETE", fullURL, nil)
	if err != nil {
		return fmt.Errorf("ошибка создания запроса: %v", err)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("ошибка выполнения запроса: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HSM вернул ошибку: %d, тело ответа: %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}
