package usecase

import (
	"errors"
	"sstu-go-forum-auth-service/internal/repository"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
	"sstu-go-forum-auth-service/internal/model"
	"sstu-go-forum-auth-service/internal/utils"
)

type AuthUseCase struct {
	Repo repository.AuthRepository
}

func NewAuthUseCase(repo repository.AuthRepository) *AuthUseCase {
	log.Info().Msg("AuthUseCase initialized")
	return &AuthUseCase{Repo: repo}
}

func (uc *AuthUseCase) Register(u *model.User) (*model.RegisterResponse, error) {
	log.Debug().Str("username", u.Username).Msg("Registering user")
	if err := u.Validate(); err != nil {
		log.Warn().Err(err).Msg("User validation failed")
		return nil, err
	}
	if existing, _ := uc.Repo.GetUserByUsername(u.Username); existing != nil {
		log.Warn().Str("username", u.Username).Msg("User already exists")
		return nil, errors.New("user already exists")
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
	log.Info().
		Int("userID", u.ID).
		Str("username", u.Username).
		Msg("User registered")
	return &model.RegisterResponse{
		Message: "Пользователь зарегистрирован",
		UserID:  u.ID,
	}, nil
}

func (uc *AuthUseCase) Login(req model.LoginRequest) (*model.AuthResponse, error) {
	log.Debug().Str("username", req.Username).Msg("Login attempt")
	user, err := uc.Repo.GetUserByUsername(req.Username)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)) != nil {
		log.Warn().Str("username", req.Username).Msg("Invalid credentials")
		return nil, errors.New("invalid credentials")
	}
	access, err := utils.GenerateAccessToken(user.ID, user.Username, user.Role)
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate access token")
		return nil, err
	}
	refresh, exp, err := utils.GenerateRefreshToken(user.ID, user.Username, user.Role)
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate refresh token")
		return nil, err
	}
	if err := uc.Repo.DeleteRefreshTokensByUserID(user.ID); err != nil {
		log.Error().Err(err).Msg("Failed to delete old refresh tokens")
		return nil, err
	}
	if err := uc.Repo.SaveRefreshToken(&model.RefreshToken{
		UserID:    user.ID,
		Token:     refresh,
		ExpiresAt: exp,
	}); err != nil {
		log.Error().Err(err).Msg("Failed to save refresh token")
		return nil, err
	}
	log.Info().
		Int("userID", user.ID).
		Str("username", user.Username).
		Msg("User logged in")
	return &model.AuthResponse{
		AccessToken:  access,
		RefreshToken: refresh,
	}, nil
}

func (uc *AuthUseCase) RefreshToken(req model.RefreshRequest) (*model.AuthResponse, error) {
	log.Debug().Msg("Token refresh attempt")
	claims, err := utils.VerifyToken(req.RefreshToken)
	if err != nil {
		log.Warn().Err(err).Msg("Refresh token verification failed")
		return nil, err
	}
	uid, ok := claims["user_id"].(float64)
	username, ok1 := claims["username"].(string)
	role, ok2 := claims["role"].(string)
	if !ok || !ok1 || !ok2 {
		log.Warn().Msg("Invalid token data")
		return nil, errors.New("invalid token data")
	}
	userID := int(uid)
	rt, err := uc.Repo.GetRefreshToken(req.RefreshToken)
	if err != nil || rt.UserID != userID || time.Now().After(rt.ExpiresAt) {
		log.Warn().Err(err).Msg("Invalid or expired refresh token")
		return nil, errors.New("invalid refresh token")
	}
	if err := uc.Repo.DeleteRefreshToken(req.RefreshToken); err != nil {
		log.Error().Err(err).Msg("Failed to delete used refresh token")
		return nil, err
	}
	newAccess, err := utils.GenerateAccessToken(userID, username, role)
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate new access token")
		return nil, err
	}
	newRefresh, newExp, err := utils.GenerateRefreshToken(userID, username, role)
	if err != nil {
		log.Error().Err(err).Msg("Failed to generate new refresh token")
		return nil, err
	}
	if err := uc.Repo.SaveRefreshToken(&model.RefreshToken{
		UserID:    userID,
		Token:     newRefresh,
		ExpiresAt: newExp,
	}); err != nil {
		log.Error().Err(err).Msg("Failed to save new refresh token")
		return nil, err
	}
	log.Info().Int("userID", userID).Msg("Refresh token successful")
	return &model.AuthResponse{
		AccessToken:  newAccess,
		RefreshToken: newRefresh,
	}, nil
}
