package usecase

import (
	"sstu-go-forum-auth-service/internal/dto"
	"sstu-go-forum-auth-service/internal/model"
)

type AuthUseCase interface {
	Register(u *model.User) (*model.User, error) // TODO: вынести формирование ответа клиенту в handler
	Login(req dto.LoginRequest) (*model.User, string, string, error)
	RefreshToken(req dto.RefreshRequest) (*model.User, string, string, error)
}
