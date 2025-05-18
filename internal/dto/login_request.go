package dto

// LoginRequest представляет запрос на авторизацию пользователя
// @Description Структура запроса для авторизации пользователя с его данными
type LoginRequest struct {
	Username string `json:"username"` // Имя пользователя
	Password string `json:"password"` // Пароль пользователя
}
