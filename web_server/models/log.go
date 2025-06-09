package models

import "time"

type Log struct {
    ID        int
    UserID    int // Теперь int, так как NULL исключён
    Action    string
    Details   string
    CreatedAt time.Time
}