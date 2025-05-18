package dto

// RegisterResponse представляет ответ на запрос регистрации
// @Description Структура ответа при успешной регистрации пользователя
type RegisterResponse struct {
	Message string `json:"message"` // Сообщение о статусе регистрации
	UserID  int    `json:"user_id"` // ID зарегистрированного пользователя
}
