package models

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"log"
	"myproject/hsm"
	"strconv"
	"time"
)

// SignedDocuments представляет подписанный документ
type SignedDocuments struct {
	ID              int
	FileID          int
	KeyID           int
	Filename        string
	SignedFilePath  string
	PublicKeyPath   string
	SignaturePath   string
	CertificatePath string
	SignedAt        time.Time
	Bank            string
}

func FindSignedDocumentByKeyAndCert(db *sql.DB, publicKeyData, certData, signatureData, signedFileData []byte) (*SignedDocuments, error) {
	var doc SignedDocuments
	query := `
        SELECT 
            sd.id, 
            sd.file_id, 
            sd.key_id, 
            f.filename, 
            sd.signed_file_path, 
            sd.public_key_path, 
            sd.signature_path, 
            sd.certificate_path, 
            sd.signed_at,
            s.bank
        FROM 
            signed_documents sd
        JOIN 
            files f ON sd.file_id = f.id
        JOIN
            signatures s ON sd.key_id = s.id
        WHERE 
            sd.public_key_path IS NOT NULL 
            AND sd.certificate_path IS NOT NULL`
	rows, err := db.Query(query)
	if err != nil {
		log.Printf("Ошибка выполнения SQL-запроса: %v", err)
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		err := rows.Scan(&doc.ID, &doc.FileID, &doc.KeyID, &doc.Filename, &doc.SignedFilePath, &doc.PublicKeyPath, &doc.SignaturePath, &doc.CertificatePath, &doc.SignedAt, &doc.Bank)
		if err != nil {
			log.Printf("Ошибка сканирования строки: %v", err)
			return nil, err
		}

		// Получение user_id из таблицы signatures
		var userID int
		err = db.QueryRow("SELECT user_id FROM signatures WHERE id = ?", doc.KeyID).Scan(&userID)
		if err != nil {
			log.Printf("Ошибка получения user_id для keyID=%d: %v", doc.KeyID, err)
			continue
		}
		userIDStr := strconv.Itoa(userID)
		log.Printf("Извлечен userID=%s для keyID=%d", userIDStr, doc.KeyID)

		// Получение подписи из HSM
		log.Printf("Попытка извлечения подписи из HSM: userID=%s, path=%s", userIDStr, doc.SignaturePath)
		storedSignature, err := hsm.Retrieve(userIDStr, "signature", doc.SignaturePath)
		if err != nil {
			log.Printf("Ошибка получения подписи из HSM для пути %s: %v", doc.SignaturePath, err)
			continue
		}
		if storedSignature == nil {
			log.Printf("Подпись не найдена в HSM для пути %s", doc.SignaturePath)
			continue
		}

		// Проверка совпадения подписи
		if !bytes.Equal(storedSignature, signatureData) {
			log.Printf("Подпись из архива не совпадает с подписью в HSM для пути %s", doc.SignaturePath)
			continue
		}

		// Получение публичного ключа из HSM
		hsmPublicKeyPath := doc.PublicKeyPath
		log.Printf("Попытка извлечения публичного ключа из HSM: userID=%s, path=%s", userIDStr, hsmPublicKeyPath)
		storedPublicKey, err := hsm.Retrieve(userIDStr, "key", hsmPublicKeyPath)
		if err != nil {
			log.Printf("Ошибка получения публичного ключа из HSM для пути %s: %v", hsmPublicKeyPath, err)
			continue
		}

		// Получение сертификата из HSM
		hsmCertificatePath := doc.CertificatePath
		log.Printf("Попытка извлечения сертификата из HSM: userID=%s, path=%s", userIDStr, hsmCertificatePath)
		storedCert, err := hsm.Retrieve(userIDStr, "cert", hsmCertificatePath)
		if err != nil {
			log.Printf("Ошибка получения сертификата из HSM для пути %s: %v", hsmCertificatePath, err)
			continue
		}

		// Декодирование сертификата
		certBlock, _ := pem.Decode(storedCert)
		if certBlock == nil {
			log.Printf("Ошибка декодирования сертификата для пути %s", hsmCertificatePath)
			continue
		}
		cert, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			log.Printf("Ошибка парсинга сертификата для пути %s: %v", hsmCertificatePath, err)
			continue
		}

		// Проверка цепочки доверия сертификата
		roots := x509.NewCertPool()
		intermediates := x509.NewCertPool()

		// Загрузка корневого сертификата
		rootCertData, err := hsm.Retrieve("system", "cert", "/root_cert.pem")
		if err != nil {
			log.Printf("Ошибка получения корневого сертификата: %v", err)
			continue
		}
		rootBlock, _ := pem.Decode(rootCertData)
		if rootBlock == nil {
			log.Printf("Ошибка декодирования корневого сертификата")
			continue
		}
		rootCert, err := x509.ParseCertificate(rootBlock.Bytes)
		if err != nil {
			log.Printf("Ошибка парсинга корневого сертификата: %v", err)
			continue
		}
		roots.AddCert(rootCert)

		// Загрузка промежуточного сертификата
		intermediateCertData, err := hsm.Retrieve("system", "cert", "/intermediate_cert.pem")
		if err != nil {
			log.Printf("Ошибка получения промежуточного сертификата: %v", err)
			continue
		}
		intermediateBlock, _ := pem.Decode(intermediateCertData)
		if intermediateBlock == nil {
			log.Printf("Ошибка декодирования промежуточного сертификата")
			continue
		}
		intermediateCert, err := x509.ParseCertificate(intermediateBlock.Bytes)
		if err != nil {
			log.Printf("Ошибка парсинга промежуточного сертификата: %v", err)
			continue
		}
		intermediates.AddCert(intermediateCert)

		opts := x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		}
		if _, err := cert.Verify(opts); err != nil {
			log.Printf("Сертификат не принадлежит нашей системе для пути %s: %v", hsmCertificatePath, err)
			continue
		}

		// Проверка совпадения публичного ключа и сертификата
		if !bytes.Equal(storedPublicKey, publicKeyData) {
			log.Printf("Публичный ключ не совпадает для пути %s", hsmPublicKeyPath)
			continue
		}
		if !bytes.Equal(storedCert, certData) {
			log.Printf("Сертификат не совпадает для пути %s", hsmCertificatePath)
			continue
		}

		// Проверка подписи с использованием файла из архива
		publicKeyBlock, _ := pem.Decode(storedPublicKey)
		if publicKeyBlock == nil {
			log.Printf("Ошибка декодирования публичного ключа для пути %s", hsmPublicKeyPath)
			continue
		}
		rsaPublicKey, err := x509.ParsePKCS1PublicKey(publicKeyBlock.Bytes)
		if err != nil {
			log.Printf("Ошибка парсинга публичного ключа для пути %s: %v", hsmPublicKeyPath, err)
			continue
		}

		hashed := sha256.Sum256(signedFileData)
		log.Printf("Хэш файла из архива при проверке: %x", hashed[:])
		err = rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA256, hashed[:], signatureData)
		if err != nil {
			log.Printf("Подпись недействительна для файла из архива: %v", err)
			continue
		}

		log.Printf("Найден документ: ID=%d, Filename=%s, UserID=%s", doc.ID, doc.Filename, userIDStr)
		return &doc, nil
	}
	log.Printf("Документ не найден: нет совпадений по публичному ключу, сертификату и подписи")
	return nil, nil
}
