package models

type Signature struct {
	ID              int
	UserID          int
	Bank            string
	PublicKeyPath   *string
	PrivateKeyPath  *string
	CertificatePath *string
}
