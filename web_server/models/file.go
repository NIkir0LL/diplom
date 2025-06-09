package models

import "time"

type File struct {
    ID       int
    UserID   int
    Filename string
    Filepath string
    UploadedAt time.Time // Добавьте это поле
}