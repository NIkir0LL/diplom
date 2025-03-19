package models

type Key struct {
    ID               int
    UserID           int
    UserName         string 
    Bank             string
    PublicKeyPath    string
    PrivateKeyPath   string
    CertificatePath  string
}