package main

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"
)

var (
	masterKey     []byte
	dataDir       = "data"
	logsDir       = "logs"
	masterKeyFile = "master.key"
	logger        *log.Logger
)

func initLogger() {
	if err := os.MkdirAll(logsDir, 0755); err != nil {
		log.Fatalf("Ошибка создания директории логов: %v", err)
	}
	logFileName := fmt.Sprintf("hsm_server_%s.log", time.Now().Format("2006-01-02"))
	logFilePath := filepath.Join(logsDir, logFileName)
	logFile := &lumberjack.Logger{
		Filename:   logFilePath,
		MaxSize:    10,
		MaxBackups: 3,
		MaxAge:     28,
		Compress:   true,
	}
	logger = log.New(logFile, "", log.LstdFlags)
	logger.Printf("[INFO] [init] Логирование инициализировано, файл: %s", logFilePath)
}

func main() {
	initLogger()
	var err error
	if _, err = os.Stat(masterKeyFile); os.IsNotExist(err) {
		logger.Printf("[INFO] [main] Файл мастер-ключа не найден, генерируем новый: %s", masterKeyFile)
		masterKey = make([]byte, 32)
		if _, err = rand.Read(masterKey); err != nil {
			logger.Printf("[ERROR] [main] Ошибка генерации мастер-ключа: %v", err)
			log.Fatalf("Ошибка генерации мастер-ключа: %v", err)
		}
		if err = os.WriteFile(masterKeyFile, masterKey, 0600); err != nil {
			logger.Printf("[ERROR] [main] Ошибка сохранения мастер-ключа: %v", err)
			log.Fatalf("Ошибка сохранения мастер-ключа: %v", err)
		}
		logger.Printf("[INFO] [main] Новый мастер-ключ создан и сохранён: %s", masterKeyFile)
	} else if err != nil {
		logger.Printf("[ERROR] [main] Ошибка проверки файла мастер-ключа: %v", err)
		log.Fatalf("Ошибка проверки файла мастер-ключа: %v", err)
	} else {
		masterKey, err = os.ReadFile(masterKeyFile)
		if err != nil {
			logger.Printf("[ERROR] [main] Ошибка чтения мастер-ключа: %v", err)
			log.Fatalf("Ошибка чтения мастер-ключа: %v", err)
		}
	}
	if len(masterKey) != 32 {
		logger.Printf("[ERROR] [main] Недопустимая длина мастер-ключа: %d байт, ожидается 32", len(masterKey))
		log.Fatalf("Недопустимая длина мастер-ключа: %d байт, ожидается 32", len(masterKey))
	}
	logger.Printf("[INFO] [main] Мастер-ключ загружен, длина: %d байт", len(masterKey))
	testCrypto()
	if err = os.MkdirAll(dataDir, 0755); err != nil {
		logger.Printf("[ERROR] [main] Ошибка создания директории данных: %v", err)
		log.Fatalf("Ошибка создания директории данных: %v", err)
	}
	logger.Printf("[INFO] [main] Директория данных создана: %s", dataDir)
	http.HandleFunc("/store", storeHandler)
	http.HandleFunc("/retrieve", retrieveHandler)
	http.HandleFunc("/sign", signHandler)
	http.HandleFunc("/delete", deleteHandler)
	logger.Println("[INFO] [main] Сервер запущен на :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func testCrypto() {
	data := []byte("-----BEGIN RSA PRIVATE KEY-----\nTestKeyData\n-----END RSA PRIVATE KEY-----\n")
	enc, err := encrypt(data)
	if err != nil {
		logger.Printf("[ERROR] [testCrypto] Ошибка шифрования: %v", err)
		log.Fatalf("Ошибка шифрования в тесте: %v", err)
	}
	dec, err := decrypt(enc)
	if err != nil {
		logger.Printf("[ERROR] [testCrypto] Ошибка расшифровки: %v", err)
		log.Fatalf("Ошибка расшифровки в тесте: %v", err)
	}
	if string(dec) != string(data) {
		logger.Printf("[ERROR] [testCrypto] Данные не совпадают: оригинал=%s, расшифровано=%s", data, dec)
		log.Fatalf("Данные не совпадают в тесте шифрования/расшифровки")
	}
	logger.Printf("[INFO] [testCrypto] Тест шифрования/расшифровки успешен")
}

func getSafePath(userID, fileType, filePath string) (string, error) {
	if strings.Contains(userID, "..") || strings.Contains(fileType, "..") || strings.Contains(filePath, "..") {
		return "", fmt.Errorf("недопустимый путь: содержит '..'")
	}
	if !strings.HasPrefix(filePath, "/") {
		return "", fmt.Errorf("путь должен начинаться с '/'")
	}
	effectiveType := fileType
	if fileType == "key" {
		effectiveType = "keys"
	}
	safePath := filepath.Join(dataDir, "users", userID, effectiveType, filePath[1:])
	if !strings.HasPrefix(safePath, dataDir) {
		return "", fmt.Errorf("попытка выхода за пределы директории данных")
	}
	return safePath, nil
}

func encrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания AES-шифра: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания GCM: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("ошибка генерации nonce: %v", err)
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

func decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания AES-шифра: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания GCM: %v", err)
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("недостаточная длина зашифрованных данных")
	}
	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("ошибка расшифровки: %v", err)
	}
	return plaintext, nil
}

func storeHandler(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	if r.Method != http.MethodPost {
		logger.Printf("[ERROR] [storeHandler] Неподдерживаемый метод: %s, remote_addr=%s", r.Method, r.RemoteAddr)
		http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		logger.Printf("[ERROR] [storeHandler] Ошибка парсинга формы: %v, remote_addr=%s", err, r.RemoteAddr)
		http.Error(w, fmt.Sprintf("Ошибка парсинга формы: %v", err), http.StatusBadRequest)
		return
	}
	userID := r.FormValue("user_id")
	fileType := r.FormValue("type")
	filePath := r.FormValue("path")
	file, _, err := r.FormFile("data")
	if err != nil {
		logger.Printf("[ERROR] [storeHandler] Ошибка получения файла: %v, remote_addr=%s", err, r.RemoteAddr)
		http.Error(w, fmt.Sprintf("Ошибка получения файла: %v", err), http.StatusBadRequest)
		return
	}
	defer file.Close()
	if userID == "" || fileType == "" || filePath == "" {
		logger.Printf("[ERROR] [storeHandler] Отсутствуют обязательные параметры: user_id=%s, type=%s, path=%s, remote_addr=%s", userID, fileType, filePath, r.RemoteAddr)
		http.Error(w, "Отсутствуют обязательные параметры", http.StatusBadRequest)
		return
	}
	logger.Printf("[INFO] [storeHandler] Входящий запрос: user_id=%s, type=%s, path=%s, метод=%s, remote_addr=%s", userID, fileType, filePath, r.Method, r.RemoteAddr)
	safePath, err := getSafePath(userID, fileType, filePath)
	if err != nil {
		logger.Printf("[ERROR] [storeHandler] Ошибка формирования пути: %v, user_id=%s, type=%s, path=%s, remote_addr=%s", err, userID, fileType, filePath, r.RemoteAddr)
		http.Error(w, fmt.Sprintf("Ошибка формирования пути: %v", err), http.StatusBadRequest)
		return
	}
	data, err := io.ReadAll(file)
	if err != nil {
		logger.Printf("[ERROR] [storeHandler] Ошибка чтения файла: %v, user_id=%s, type=%s, path=%s, remote_addr=%s", err, userID, fileType, filePath, r.RemoteAddr)
		http.Error(w, fmt.Sprintf("Ошибка чтения файла: %v", err), http.StatusInternalServerError)
		return
	}
	logger.Printf("[INFO] [storeHandler] Файл прочитан, размер: %d байт, user_id=%s, type=%s, path=%s", len(data), userID, fileType, filePath)
	ciphertext, err := encrypt(data)
	if err != nil {
		logger.Printf("[ERROR] [storeHandler] Ошибка шифрования: %v, user_id=%s, type=%s, path=%s, remote_addr=%s", err, userID, fileType, filePath, r.RemoteAddr)
		http.Error(w, fmt.Sprintf("Ошибка шифрования: %v", err), http.StatusInternalServerError)
		return
	}
	if err := os.MkdirAll(filepath.Dir(safePath), 0755); err != nil {
		logger.Printf("[ERROR] [storeHandler] Ошибка создания директории: %v, user_id=%s, type=%s, path=%s, remote_addr=%s", err, userID, fileType, filePath, r.RemoteAddr)
		http.Error(w, fmt.Sprintf("Ошибка создания директории: %v", err), http.StatusInternalServerError)
		return
	}
	if err := os.WriteFile(safePath, ciphertext, 0644); err != nil {
		logger.Printf("[ERROR] [storeHandler] Ошибка сохранения файла: %v, user_id=%s, type=%s, path=%s, remote_addr=%s", err, userID, fileType, filePath, r.RemoteAddr)
		http.Error(w, fmt.Sprintf("Ошибка сохранения файла: %v", err), http.StatusInternalServerError)
		return
	}
	logger.Printf("[INFO] [storeHandler] Файл сохранён: user_id=%s, type=%s, path=%s, время_выполнения=%v", userID, fileType, filePath, time.Since(startTime))
	fmt.Fprint(w, "Успешно сохранено")
}

func retrieveHandler(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	if r.Method != http.MethodGet {
		logger.Printf("[ERROR] [retrieveHandler] Неподдерживаемый метод: %s, remote_addr=%s", r.Method, r.RemoteAddr)
		http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
		return
	}
	userID := r.URL.Query().Get("user_id")
	fileType := r.URL.Query().Get("type")
	filePath := r.URL.Query().Get("path")
	if userID == "" || fileType == "" || filePath == "" {
		logger.Printf("[ERROR] [retrieveHandler] Отсутствуют обязательные параметры: user_id=%s, type=%s, path=%s, remote_addr=%s", userID, fileType, filePath, r.RemoteAddr)
		http.Error(w, "Отсутствуют обязательные параметры", http.StatusBadRequest)
		return
	}
	logger.Printf("[INFO] [retrieveHandler] Входящий запрос: user_id=%s, type=%s, path=%s, метод=%s, remote_addr=%s", userID, fileType, filePath, r.Method, r.RemoteAddr)
	safePath, err := getSafePath(userID, fileType, filePath)
	if err != nil {
		logger.Printf("[ERROR] [retrieveHandler] Ошибка формирования пути: %v, user_id=%s, type=%s, path=%s, remote_addr=%s", err, userID, fileType, filePath, r.RemoteAddr)
		http.Error(w, fmt.Sprintf("Ошибка формирования пути: %v", err), http.StatusBadRequest)
		return
	}
	if _, err := os.Stat(safePath); os.IsNotExist(err) {
		logger.Printf("[ERROR] [retrieveHandler] Файл не найден: user_id=%s, type=%s, path=%s, remote_addr=%s", userID, fileType, filePath, r.RemoteAddr)
		http.Error(w, "Файл не найден", http.StatusNotFound)
		return
	} else if err != nil {
		logger.Printf("[ERROR] [retrieveHandler] Ошибка проверки файла: %v, user_id=%s, type=%s, path=%s, remote_addr=%s", err, userID, fileType, filePath, r.RemoteAddr)
		http.Error(w, fmt.Sprintf("Ошибка проверки файла: %v", err), http.StatusInternalServerError)
		return
	}
	ciphertext, err := os.ReadFile(safePath)
	if err != nil {
		logger.Printf("[ERROR] [retrieveHandler] Ошибка чтения файла: %v, user_id=%s, type=%s, path=%s, remote_addr=%s", err, userID, fileType, filePath, r.RemoteAddr)
		http.Error(w, fmt.Sprintf("Ошибка чтения файла: %v", err), http.StatusInternalServerError)
		return
	}
	logger.Printf("[INFO] [retrieveHandler] Файл прочитан, размер зашифрованных данных: %d байт, user_id=%s, type=%s, path=%s", len(ciphertext), userID, fileType, filePath)
	data, err := decrypt(ciphertext)
	if err != nil {
		logger.Printf("[ERROR] [retrieveHandler] Ошибка расшифровки: %v, user_id=%s, type=%s, path=%s, remote_addr=%s", err, userID, fileType, filePath, r.RemoteAddr)
		http.Error(w, fmt.Sprintf("Ошибка расшифровки: %v", err), http.StatusInternalServerError)
		return
	}
	logger.Printf("[INFO] [retrieveHandler] Файл расшифрован, размер: %d байт, user_id=%s, type=%s, path=%s", len(data), userID, fileType, filePath)
	logger.Printf("[INFO] [retrieveHandler] Файл извлечён: user_id=%s, type=%s, path=%s, время_выполнения=%v", userID, fileType, filePath, time.Since(startTime))
	w.Write(data)
}

func deleteHandler(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	if r.Method != http.MethodDelete {
		logger.Printf("[ERROR] [deleteHandler] Неподдерживаемый метод: %s, remote_addr=%s", r.Method, r.RemoteAddr)
		http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
		return
	}
	userID := r.URL.Query().Get("user_id")
	fileType := r.URL.Query().Get("type")
	filePath := r.URL.Query().Get("path")
	if userID == "" || fileType == "" || filePath == "" {
		logger.Printf("[ERROR] [deleteHandler] Отсутствуют обязательные параметры: user_id=%s, type=%s, path=%s, remote_addr=%s", userID, fileType, filePath, r.RemoteAddr)
		http.Error(w, "Отсутствуют обязательные параметры", http.StatusBadRequest)
		return
	}
	logger.Printf("[INFO] [deleteHandler] Входящий запрос: user_id=%s, type=%s, path=%s, метод=%s, remote_addr=%s", userID, fileType, filePath, r.Method, r.RemoteAddr)
	safePath, err := getSafePath(userID, fileType, filePath)
	if err != nil {
		logger.Printf("[ERROR] [deleteHandler] Ошибка формирования пути: %v, user_id=%s, type=%s, path=%s, remote_addr=%s", err, userID, fileType, filePath, r.RemoteAddr)
		http.Error(w, fmt.Sprintf("Ошибка формирования пути: %v", err), http.StatusBadRequest)
		return
	}
	if _, err := os.Stat(safePath); os.IsNotExist(err) {
		logger.Printf("[ERROR] [deleteHandler] Файл не найден: user_id=%s, type=%s, path=%s, remote_addr=%s", userID, fileType, filePath, r.RemoteAddr)
		http.Error(w, "Файл не найден", http.StatusNotFound)
		return
	} else if err != nil {
		logger.Printf("[ERROR] [deleteHandler] Ошибка проверки файла: %v, user_id=%s, type=%s, path=%s, remote_addr=%s", err, userID, fileType, filePath, r.RemoteAddr)
		http.Error(w, fmt.Sprintf("Ошибка проверки файла: %v", err), http.StatusInternalServerError)
		return
	}
	if err := os.Remove(safePath); err != nil {
		logger.Printf("[ERROR] [deleteHandler] Ошибка удаления файла: %v, user_id=%s, type=%s, path=%s, remote_addr=%s", err, userID, fileType, filePath, r.RemoteAddr)
		http.Error(w, fmt.Sprintf("Ошибка удаления файла: %v", err), http.StatusInternalServerError)
		return
	}
	logger.Printf("[INFO] [deleteHandler] Файл удалён: user_id=%s, type=%s, path=%s, время_выполнения=%v", userID, fileType, filePath, time.Since(startTime))
	fmt.Fprint(w, "Файл успешно удалён")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func signHandler(w http.ResponseWriter, r *http.Request) {
    startTime := time.Now()
    if r.Method != http.MethodPost {
        logger.Printf("[ERROR] [signHandler] Неподдерживаемый метод: %s, remote_addr=%s", r.Method, r.RemoteAddr)
        http.Error(w, "Метод не поддерживается", http.StatusMethodNotAllowed)
        return
    }
    if err := r.ParseMultipartForm(32 << 20); err != nil {
        logger.Printf("[ERROR] [signHandler] Ошибка парсинга формы: %v, remote_addr=%s", err, r.RemoteAddr)
        http.Error(w, fmt.Sprintf("Ошибка парсинга формы: %v", err), http.StatusBadRequest)
        return
    }
    userID := r.FormValue("user_id")
    fileType := r.FormValue("type")
    keyPath := r.FormValue("key_path")
    publicKeyPath := r.FormValue("public_key_path")
    file, _, err := r.FormFile("data")
    if err != nil {
        logger.Printf("[ERROR] [signHandler] Ошибка получения файла данных: %v, remote_addr=%s", err, r.RemoteAddr)
        http.Error(w, fmt.Sprintf("Ошибка получения файла данных: %v", err), http.StatusBadRequest)
        return
    }
    defer file.Close()
    if userID == "" || fileType == "" || keyPath == "" || publicKeyPath == "" {
        logger.Printf("[ERROR] [signHandler] Отсутствуют обязательные параметры: user_id=%s, type=%s, key_path=%s, public_key_path=%s, remote_addr=%s", userID, fileType, keyPath, publicKeyPath, r.RemoteAddr)
        http.Error(w, "Отсутствуют обязательные параметры", http.StatusBadRequest)
        return
    }
    logger.Printf("[INFO] [signHandler] Входящий запрос: user_id=%s, type=%s, key_path=%s, public_key_path=%s, метод=%s, remote_addr=%s", userID, fileType, keyPath, publicKeyPath, r.Method, r.RemoteAddr)
    
    // Формирование безопасных путей
    safeKeyPath, err := getSafePath(userID, fileType, keyPath)
    if err != nil {
        logger.Printf("[ERROR] [signHandler] Ошибка формирования пути к ключу: %v, user_id=%s, type=%s, key_path=%s, remote_addr=%s", err, userID, fileType, keyPath, r.RemoteAddr)
        http.Error(w, fmt.Sprintf("Ошибка формирования пути к ключу: %v", err), http.StatusBadRequest)
        return
    }
    safePublicKeyPath, err := getSafePath(userID, fileType, publicKeyPath)
    if err != nil {
        logger.Printf("[ERROR] [signHandler] Ошибка формирования пути к публичному ключу: %v, user_id=%s, type=%s, public_key_path=%s, remote_addr=%s", err, userID, fileType, publicKeyPath, r.RemoteAddr)
        http.Error(w, fmt.Sprintf("Ошибка формирования пути к публичному ключу: %v", err), http.StatusBadRequest)
        return
    }
    
    // Проверка существования ключей
    if _, err := os.Stat(safeKeyPath); os.IsNotExist(err) {
        logger.Printf("[ERROR] [signHandler] Ключ не найден: user_id=%s, type=%s, key_path=%s, remote_addr=%s", userID, fileType, keyPath, r.RemoteAddr)
        http.Error(w, "Ключ не найден", http.StatusNotFound)
        return
    } else if err != nil {
        logger.Printf("[ERROR] [signHandler] Ошибка проверки ключа: %v, user_id=%s, type=%s, key_path=%s, remote_addr=%s", err, userID, fileType, keyPath, r.RemoteAddr)
        http.Error(w, fmt.Sprintf("Ошибка проверки ключа: %v", err), http.StatusInternalServerError)
        return
    }
    if _, err := os.Stat(safePublicKeyPath); os.IsNotExist(err) {
        logger.Printf("[ERROR] [signHandler] Публичный ключ не найден: user_id=%s, type=%s, public_key_path=%s, remote_addr=%s", userID, fileType, publicKeyPath, r.RemoteAddr)
        http.Error(w, "Публичный ключ не найден", http.StatusNotFound)
        return
    } else if err != nil {
        logger.Printf("[ERROR] [signHandler] Ошибка проверки публичного ключа: %v, user_id=%s, type=%s, public_key_path=%s, remote_addr=%s", err, userID, fileType, publicKeyPath, r.RemoteAddr)
        http.Error(w, fmt.Sprintf("Ошибка проверки публичного ключа: %v", err), http.StatusInternalServerError)
        return
    }
    
    // Загрузка и расшифровка приватного ключа
    ciphertext, err := os.ReadFile(safeKeyPath)
    if err != nil {
        logger.Printf("[ERROR] [signHandler] Ошибка чтения файла ключа: %v, user_id=%s, type=%s, key_path=%s, remote_addr=%s", err, userID, fileType, keyPath, r.RemoteAddr)
        http.Error(w, fmt.Sprintf("Ошибка чтения файла ключа: %v", err), http.StatusInternalServerError)
        return
    }
    logger.Printf("[INFO] [signHandler] Ключ прочитан, размер: %d байт, user_id=%s, type=%s, key_path=%s", len(ciphertext), userID, fileType, keyPath)
    privateKeyData, err := decrypt(ciphertext)
    if err != nil {
        logger.Printf("[ERROR] [signHandler] Ошибка расшифровки ключа: %v, user_id=%s, type=%s, key_path=%s, remote_addr=%s", err, userID, fileType, keyPath, r.RemoteAddr)
        http.Error(w, fmt.Sprintf("Ошибка расшифровки ключа: %v", err), http.StatusInternalServerError)
        return
    }
    logger.Printf("[INFO] [signHandler] Ключ расшифрован, размер: %d байт, user_id=%s, type=%s, key_path=%s", len(privateKeyData), userID, fileType, keyPath)
    
    // Парсинг приватного ключа
    block, rest := pem.Decode(privateKeyData)
    if block == nil || len(rest) > 0 {
        logger.Printf("[ERROR] [signHandler] Ошибка декодирования PEM, остаток: %d байт, user_id=%s, type=%s, key_path=%s, remote_addr=%s", len(rest), userID, fileType, keyPath, r.RemoteAddr)
        http.Error(w, "Ошибка декодирования ключа: неверный формат PEM или лишние данные", http.StatusBadRequest)
        return
    }
    var privateKey *rsa.PrivateKey
    if block.Type == "RSA PRIVATE KEY" {
        privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
        if err != nil {
            logger.Printf("[ERROR] [signHandler] Ошибка парсинга PKCS1 ключа: %v, user_id=%s, type=%s, key_path=%s, remote_addr=%s", err, userID, fileType, keyPath, r.RemoteAddr)
            http.Error(w, fmt.Sprintf("Ошибка парсинга ключа: %v", err), http.StatusBadRequest)
            return
        }
    } else if block.Type == "PRIVATE KEY" {
        key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
        if err != nil {
            logger.Printf("[ERROR] [signHandler] Ошибка парсинга PKCS8 ключа: %v, user_id=%s, type=%s, key_path=%s, remote_addr=%s", err, userID, fileType, keyPath, r.RemoteAddr)
            http.Error(w, fmt.Sprintf("Ошибка парсинга ключа: %v", err), http.StatusBadRequest)
            return
        }
        var ok bool
        privateKey, ok = key.(*rsa.PrivateKey)
        if !ok {
            logger.Printf("[ERROR] [signHandler] Ключ не является RSA ключом, user_id=%s, type=%s, key_path=%s, remote_addr=%s", userID, fileType, keyPath, r.RemoteAddr)
            http.Error(w, "Ключ не является RSA ключом", http.StatusBadRequest)
            return
        }
    } else {
        logger.Printf("[ERROR] [signHandler] Неподдерживаемый тип ключа: %s, user_id=%s, type=%s, key_path=%s, remote_addr=%s", block.Type, userID, fileType, keyPath, r.RemoteAddr)
        http.Error(w, fmt.Sprintf("Неподдерживаемый тип ключа: %s", block.Type), http.StatusBadRequest)
        return
    }
    logger.Printf("[INFO] [signHandler] Ключ успешно распарсен, user_id=%s, type=%s, key_path=%s", userID, fileType, keyPath)
    
    // Загрузка и расшифровка публичного ключа
    publicKeyCiphertext, err := os.ReadFile(safePublicKeyPath)
    if err != nil {
        logger.Printf("[ERROR] [signHandler] Ошибка чтения файла публичного ключа: %v, user_id=%s, type=%s, public_key_path=%s, remote_addr=%s", err, userID, fileType, publicKeyPath, r.RemoteAddr)
        http.Error(w, fmt.Sprintf("Ошибка чтения файла публичного ключа: %v", err), http.StatusInternalServerError)
        return
    }
    publicKeyData, err := decrypt(publicKeyCiphertext)
    if err != nil {
        logger.Printf("[ERROR] [signHandler] Ошибка расшифровки публичного ключа: %v, user_id=%s, type=%s, public_key_path=%s, remote_addr=%s", err, userID, fileType, publicKeyPath, r.RemoteAddr)
        http.Error(w, fmt.Sprintf("Ошибка расшифровки публичного ключа: %v", err), http.StatusInternalServerError)
        return
    }
    publicKeyBlock, _ := pem.Decode(publicKeyData)
    if publicKeyBlock == nil {
        logger.Printf("[ERROR] [signHandler] Ошибка декодирования PEM публичного ключа, user_id=%s, type=%s, public_key_path=%s, remote_addr=%s", userID, fileType, publicKeyPath, r.RemoteAddr)
        http.Error(w, "Ошибка декодирования публичного ключа: неверный формат PEM", http.StatusBadRequest)
        return
    }
    publicKey, err := x509.ParsePKCS1PublicKey(publicKeyBlock.Bytes)
    if err != nil {
        logger.Printf("[ERROR] [signHandler] Ошибка парсинга публичного ключа: %v, user_id=%s, type=%s, public_key_path=%s, remote_addr=%s", err, userID, fileType, publicKeyPath, r.RemoteAddr)
        http.Error(w, fmt.Sprintf("Ошибка парсинга публичного ключа: %v", err), http.StatusBadRequest)
        return
    }
    logger.Printf("[INFO] [signHandler] Публичный ключ успешно распарсен, user_id=%s, type=%s, public_key_path=%s", userID, fileType, publicKeyPath)
    
    // Чтение хэша напрямую (данные уже являются хэшем)
    hashData, err := io.ReadAll(file)
    if err != nil {
        logger.Printf("[ERROR] [signHandler] Ошибка чтения хэша: %v, user_id=%s, type=%s, key_path=%s, remote_addr=%s", err, userID, fileType, keyPath, r.RemoteAddr)
        http.Error(w, fmt.Sprintf("Ошибка чтения хэша: %v", err), http.StatusBadRequest)
        return
    }
    if len(hashData) != sha256.Size {
        logger.Printf("[ERROR] [signHandler] Неверная длина хэша: %d, ожидается %d, user_id=%s, type=%s, key_path=%s, remote_addr=%s", len(hashData), sha256.Size, userID, fileType, keyPath, r.RemoteAddr)
        http.Error(w, fmt.Sprintf("Неверная длина хэша: %d, ожидается %d", len(hashData), sha256.Size), http.StatusBadRequest)
        return
    }
    logger.Printf("[INFO] [signHandler] Хэш получен, размер: %d байт, user_id=%s, type=%s, key_path=%s", len(hashData), userID, fileType, keyPath)
    
    // Создание подписи
    signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashData)
    if err != nil {
        logger.Printf("[ERROR] [signHandler] Ошибка подписи: %v, user_id=%s, type=%s, key_path=%s, remote_addr=%s", err, userID, fileType, keyPath, r.RemoteAddr)
        http.Error(w, fmt.Sprintf("Ошибка подписи: %v", err), http.StatusInternalServerError)
        return
    }
    logger.Printf("[INFO] [signHandler] Подпись создана, размер: %d байт, user_id=%s, type=%s, key_path=%s", len(signature), userID, fileType, keyPath)
    
    // Локальная верификация подписи
    err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashData, signature)
    if err != nil {
        logger.Printf("[ERROR] [signHandler] Локальная верификация подписи не удалась: %v, user_id=%s, type=%s, key_path=%s, public_key_path=%s, remote_addr=%s", err, userID, fileType, keyPath, publicKeyPath, r.RemoteAddr)
        http.Error(w, fmt.Sprintf("Локальная верификация подписи не удалась: %v", err), http.StatusInternalServerError)
        return
    }
    logger.Printf("[INFO] [signHandler] Локальная верификация подписи успешна, user_id=%s, type=%s, key_path=%s, public_key_path=%s", userID, fileType, keyPath, publicKeyPath)
    
    // Отправка подписи клиенту
    logger.Printf("[INFO] [signHandler] Подпись отправлена клиенту, user_id=%s, type=%s, key_path=%s, время_выполнения=%v", userID, fileType, keyPath, time.Since(startTime))
    w.Write(signature)
}