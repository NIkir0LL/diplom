package models

import "time"

type SignedDocument struct {
    ID               int
    FileID           int
    KeyID            int
    SignedFilePath   string
    SignaturePath    string
    PublicKeyPath    string
    CertificatePath  string
    SignedAt         *time.Time
    Filename         string // Добавьте это поле, если оно отсутствует
    Bank             string // Добавьте это поле, если оно отсутствует
}
