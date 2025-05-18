package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"sstu-go-forum-auth-service/internal/dto"

	"sstu-go-forum-auth-service/internal/model"
	"sstu-go-forum-auth-service/internal/usecase"
)

type AuthHandler struct {
	UseCase usecase.AuthUseCase
}

func NewAuthHandler(uc usecase.AuthUseCase) *AuthHandler { // TODO: принимать аргумент-интерфейс
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

	createdUser, err := h.UseCase.Register(&u)
	if err != nil {
		switch {
		case errors.Is(err, usecase.ErrUserAlreadyExists):
			http.Error(w, err.Error(), http.StatusBadRequest)
		default:
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
		return
	}

	resp := dto.RegisterResponse{
		Message: "Пользователь зарегистрирован",
		UserID:  createdUser.ID,
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

	var req dto.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	_, access, refresh, err := h.UseCase.Login(req)
	if err != nil {
		switch {
		case errors.Is(err, usecase.ErrInvalidCredentials):
			http.Error(w, err.Error(), http.StatusUnauthorized)
		default:
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
		return
	}

	resp := dto.AuthResponse{
		AccessToken:  access,
		RefreshToken: refresh,
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

	var req dto.RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	_, access, refresh, err := h.UseCase.RefreshToken(req)
	if err != nil {
		switch {
		case errors.Is(err, usecase.ErrInvalidTokenData),
			errors.Is(err, usecase.ErrInvalidRefreshToken):
			http.Error(w, err.Error(), http.StatusUnauthorized)
		default:
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
		return
	}

	resp := dto.AuthResponse{
		AccessToken:  access,
		RefreshToken: refresh,
	}
	json.NewEncoder(w).Encode(resp)
}
