// internal/usecase/auth_usecase.go
package usecase

import (
	"errors"
	"golang.org/x/crypto/bcrypt"
	"sstu-go-forum-auth-service/internal/domain"
	"sstu-go-forum-auth-service/internal/repository/postgres"
	"sstu-go-forum-auth-service/internal/utils"
	"time"
)

type AuthUseCase struct {
	Repo *postgres.Repository
}

func NewAuthUseCase(repo *postgres.Repository) *AuthUseCase {
	return &AuthUseCase{Repo: repo}
}

func (uc *AuthUseCase) Register(user *domain.User) error {
	existing, err := uc.Repo.GetUserByUsername(user.Username)
	if err == nil && existing != nil {
		return errors.New("user already exists")
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	user.Password = string(hashed)
	user.Role = "user"
	return uc.Repo.CreateUser(user)
}

func (uc *AuthUseCase) Login(username, password string) (string, string, error) {
	user, err := uc.Repo.GetUserByUsername(username)
	if err != nil {
		return "", "", errors.New("invalid credentials")
	}
	if bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)) != nil {
		return "", "", errors.New("invalid credentials")
	}

	access, err := utils.GenerateAccessToken(user.ID, user.Username, user.Role)
	if err != nil {
		return "", "", err
	}
	refresh, exp, err := utils.GenerateRefreshToken(user.ID, user.Username, user.Role)
	if err != nil {
		return "", "", err
	}

	if err := uc.Repo.DeleteRefreshTokensByUserID(user.ID); err != nil {
		return "", "", err
	}
	if err := uc.Repo.SaveRefreshToken(&domain.RefreshToken{
		UserID:    user.ID,
		Token:     refresh,
		ExpiresAt: exp,
	}); err != nil {
		return "", "", err
	}
	return access, refresh, nil
}

func (uc *AuthUseCase) RefreshToken(oldToken string) (string, string, error) {
	claims, err := utils.VerifyToken(oldToken)
	if err != nil {
		return "", "", err
	}

	uidf, ok := claims["user_id"].(float64)
	if !ok {
		return "", "", errors.New("invalid token data")
	}
	userID := int(uidf)

	username, ok := claims["username"].(string)
	if !ok {
		return "", "", errors.New("invalid token data")
	}
	role, ok := claims["role"].(string)
	if !ok {
		return "", "", errors.New("invalid token data")
	}

	rt, err := uc.Repo.GetRefreshToken(oldToken)
	if err != nil || rt.UserID != userID || time.Now().After(rt.ExpiresAt) {
		return "", "", errors.New("invalid refresh token")
	}
	if err := uc.Repo.DeleteRefreshToken(oldToken); err != nil {
		return "", "", err
	}

	newAccess, err := utils.GenerateAccessToken(userID, username, role)
	if err != nil {
		return "", "", err
	}
	newRefresh, newExp, err := utils.GenerateRefreshToken(userID, username, role)
	if err != nil {
		return "", "", err
	}
	if err := uc.Repo.SaveRefreshToken(&domain.RefreshToken{
		UserID:    userID,
		Token:     newRefresh,
		ExpiresAt: newExp,
	}); err != nil {
		return "", "", err
	}
	return newAccess, newRefresh, nil
}
