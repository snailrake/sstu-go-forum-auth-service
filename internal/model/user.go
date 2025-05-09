package model

import (
	"errors"
	"strings"
)

// User представляет собой пользователя системы
// @Description Структура пользователя с полями для хранения информации о пользователе
type User struct {
	ID       int    `json:"id"`       // ID пользователя
	Username string `json:"username"` // Имя пользователя
	Password string `json:"password"` // Пароль пользователя
	Role     string `json:"role"`     // Роль пользователя (USER или ADMIN)
}

func (u *User) Validate() error {
	if len(strings.TrimSpace(u.Username)) < 3 {
		return errors.New("username must be at least 3 characters")
	}
	if len(u.Password) < 6 {
		return errors.New("password must be at least 6 characters")
	}
	if u.Role != "USER" && u.Role != "ADMIN" {
		return errors.New("role must be USER or ADMIN")
	}
	return nil
}
