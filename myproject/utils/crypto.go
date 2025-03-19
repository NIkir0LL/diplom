package utils

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "encoding/pem"
    "os"
)

func GenerateKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, error) {
    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return nil, nil, err
    }
    return privateKey, &privateKey.PublicKey, nil
}

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
