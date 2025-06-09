package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"os"
)

const (
	keyFile = "data/encryption_key" // Путь к файлу с ключом шифрования
)

// GenerateKeyPair генерирует пару RSA-ключей
func GenerateKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

// SaveKeyToFile сохраняет приватный ключ в файл
func SaveKeyToFile(key *rsa.PrivateKey, filePath string) error {
	keyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()
	return pem.Encode(file, keyPEM)
}

// SavePublicKeyToFile сохраняет публичный ключ в файл
func SavePublicKeyToFile(key *rsa.PublicKey, filePath string) error {
	keyPEM := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(key),
	}
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()
	return pem.Encode(file, keyPEM)
}

// GenerateEncryptionKey генерирует ключ шифрования AES-256
func GenerateEncryptionKey() ([]byte, error) {
	key := make([]byte, 32) // 256 бит
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// SaveEncryptionKey сохраняет ключ в файл
func SaveEncryptionKey(key []byte) error {
	return os.WriteFile(keyFile, key, 0600)
}

// LoadEncryptionKey загружает ключ из файла
func LoadEncryptionKey() ([]byte, error) {
	key, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// Encrypt шифрует строку с использованием AES-256-GCM
func Encrypt(plaintext string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt дешифрует строку с использованием AES-256-GCM
func Decrypt(ciphertext string, key []byte) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	if len(data) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertextBytes := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
