package dto

// AuthResponse представляет ответ на запрос авторизации с токенами
// @Description Структура ответа для авторизации, содержащая access и refresh токены
type AuthResponse struct {
	AccessToken  string `json:"access_token"`  // Токен доступа
	RefreshToken string `json:"refresh_token"` // Токен для обновления
}
