package usecase

import (
	"sstu-go-forum-auth-service/internal/dto"
	"sstu-go-forum-auth-service/internal/repository"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
	"sstu-go-forum-auth-service/internal/model"
	"sstu-go-forum-auth-service/internal/usecase"
	"sstu-go-forum-auth-service/internal/utils"
)

type AuthUseCaseImpl struct {
	Repo repository.AuthRepository
}

func NewAuthUseCase(repo repository.AuthRepository) *AuthUseCaseImpl {
	log.Info().Msg("AuthUseCaseImpl initialized")
	return &AuthUseCaseImpl{Repo: repo}
}

func (uc *AuthUseCaseImpl) Register(u *model.User) (*model.User, error) {
	log.Debug().Str("username", u.Username).Msg("Registering user")

	if err := u.Validate(); err != nil {
		log.Warn().Err(err).Msg("User validation failed")
		return nil, err
	}
	existing, err := uc.Repo.GetUserByUsername(u.Username) // TODO: обработать ошибку
	if err != nil {
		log.Error().Err(err).Str("username", u.Username).Msg("Failed to check if user exists")
		return nil, err
	}
	if existing != nil {
		log.Warn().Str("username", u.Username).Msg("User already exists")
		return nil, usecase.ErrUserAlreadyExists // TODO: добавить работу с ошибками
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Error().Err(err).Msg("Password hashing failed")
		return nil, err
	}
	u.Password = string(hashed)

	if err := uc.Repo.CreateUser(u); err != nil {
		log.Error().Err(err).Msg("Failed to create user")
		return nil, err
	}
	log.Info().Int("userID", u.ID).Str("username", u.Username).Msg("User registered")
	return u, nil
}

func (uc *AuthUseCaseImpl) Login(req dto.LoginRequest) (*model.User, string, string, error) {
	log.Debug().Str("username", req.Username).Msg("Login attempt")

	user, err := uc.Repo.GetUserByUsername(req.Username)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)) != nil {
		log.Warn().Str("username", req.Username).Msg("Invalid credentials")
		return nil, "", "", usecase.ErrInvalidCredentials
	}

	access, err := utils.GenerateAccessToken(user.ID, user.Username, user.Role)
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate access token")
		return nil, "", "", err
	}
	refresh, exp, err := utils.GenerateRefreshToken(user.ID, user.Username, user.Role)
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate refresh token")
		return nil, "", "", err
	}
	if err := uc.Repo.DeleteRefreshTokensByUserID(user.ID); err != nil {
		log.Error().Err(err).Msg("Failed to delete old refresh tokens")
		return nil, "", "", err
	}
	if err := uc.Repo.SaveRefreshToken(&model.RefreshToken{
		UserID:    user.ID,
		Token:     refresh,
		ExpiresAt: exp,
	}); err != nil {
		log.Error().Err(err).Msg("Failed to save refresh token")
		return nil, "", "", err
	}
	log.Info().Int("userID", user.ID).Str("username", user.Username).Msg("User logged in")
	return user, access, refresh, nil
}

func (uc *AuthUseCaseImpl) RefreshToken(req dto.RefreshRequest) (*model.User, string, string, error) {
	log.Debug().Msg("Token refresh attempt")

	claims, err := utils.VerifyToken(req.RefreshToken)
	if err != nil {
		log.Warn().Err(err).Msg("Refresh token verification failed")
		return nil, "", "", err
	}
	uid, ok := claims["user_id"].(float64)
	username, ok1 := claims["username"].(string)
	role, ok2 := claims["role"].(string)
	if !ok || !ok1 || !ok2 {
		log.Warn().Msg("Invalid token data")
		return nil, "", "", usecase.ErrInvalidTokenData
	}
	userID := int(uid)

	rt, err := uc.Repo.GetRefreshToken(req.RefreshToken)
	if err != nil || rt.UserID != userID || time.Now().After(rt.ExpiresAt) {
		log.Warn().Err(err).Msg("Invalid or expired refresh token")
		return nil, "", "", usecase.ErrInvalidRefreshToken
	}
	if err := uc.Repo.DeleteRefreshToken(req.RefreshToken); err != nil {
		log.Error().Err(err).Msg("Failed to delete used refresh token")
		return nil, "", "", err
	}

	newAccess, err := utils.GenerateAccessToken(userID, username, role)
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate new access token")
		return nil, "", "", err
	}
	newRefresh, newExp, err := utils.GenerateRefreshToken(userID, username, role)
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate new refresh token")
		return nil, "", "", err
	}
	if err := uc.Repo.SaveRefreshToken(&model.RefreshToken{
		UserID:    userID,
		Token:     newRefresh,
		ExpiresAt: newExp,
	}); err != nil {
		log.Error().Err(err).Msg("Failed to save new refresh token")
		return nil, "", "", err
	}

	log.Info().Int("userID", userID).Msg("Refresh token successful")
	return &model.User{ID: userID, Username: username, Role: role}, newAccess, newRefresh, nil
}
