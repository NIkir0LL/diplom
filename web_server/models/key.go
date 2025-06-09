package models

import "time"

type Key struct {
    ID              int
    UserID          int
    UserName        string
    Bank            string
    PublicKeyPath   string
    PrivateKeyPath  string
    CertificatePath string
    NotBefore       time.Time
    NotAfter        time.Time
}