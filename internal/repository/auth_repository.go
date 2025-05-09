package repository

import "sstu-go-forum-auth-service/internal/model"

type AuthRepository interface {
	CreateUser(user *model.User) error
	GetUserByUsername(username string) (*model.User, error)
	DeleteRefreshTokensByUserID(userID int) error
	SaveRefreshToken(token *model.RefreshToken) error
	GetRefreshToken(tokenString string) (*model.RefreshToken, error)
	DeleteRefreshToken(tokenString string) error
}
