package domain

import "time"

type RefreshToken struct {
	ID        int
	UserID    int
	Token     string
	ExpiresAt time.Time
}
