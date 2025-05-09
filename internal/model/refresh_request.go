package model

// RefreshRequest представляет запрос на обновление токена
// @Description Структура запроса для обновления токена с новым refresh токеном
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"` // Refresh токен
}
