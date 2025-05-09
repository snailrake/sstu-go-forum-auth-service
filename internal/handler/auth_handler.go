package handler

import (
	"encoding/json"
	"net/http"

	"sstu-go-forum-auth-service/internal/model"
	"sstu-go-forum-auth-service/internal/usecase"
)

type AuthHandler struct {
	UseCase *usecase.AuthUseCase
}

func NewAuthHandler(uc *usecase.AuthUseCase) *AuthHandler {
	return &AuthHandler{UseCase: uc}
}

// Register обрабатывает запросы на регистрацию нового пользователя
// @Summary Регистрация нового пользователя
// @Description Функция для регистрации нового пользователя
// @Param user body model.User true "Данные пользователя для регистрации"
// @Success 200 {object} model.RegisterResponse "Ответ с информацией о регистрации"
// @Failure 400 {string} string "Неверный запрос"
// @Failure 405 {string} string "Метод не разрешён"
// @Router /register [post]
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "use POST", http.StatusMethodNotAllowed)
		return
	}
	var u model.User
	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	resp, err := h.UseCase.Register(&u)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	json.NewEncoder(w).Encode(resp)
}

// Login обрабатывает запросы на авторизацию пользователя
// @Summary Авторизация пользователя
// @Description Функция для авторизации пользователя
// @Param login_request body model.LoginRequest true "Данные для авторизации пользователя"
// @Success 200 {object} model.AuthResponse "Ответ с токенами"
// @Failure 400 {string} string "Неверный запрос"
// @Failure 401 {string} string "Неверный логин или пароль"
// @Router /login [post]
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "use POST", http.StatusMethodNotAllowed)
		return
	}
	var req model.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	resp, err := h.UseCase.Login(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	json.NewEncoder(w).Encode(resp)
}

// Refresh обрабатывает запросы на обновление токена
// @Summary Обновление токена авторизации
// @Description Функция для обновления токенов пользователя
// @Param refresh_request body model.RefreshRequest true "Данные для обновления токена"
// @Success 200 {object} model.AuthResponse "Ответ с новым токеном"
// @Failure 400 {string} string "Неверный запрос"
// @Failure 401 {string} string "Неверный токен"
// @Router /refresh [post]
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "use POST", http.StatusMethodNotAllowed)
		return
	}
	var req model.RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	resp, err := h.UseCase.RefreshToken(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	json.NewEncoder(w).Encode(resp)
}
