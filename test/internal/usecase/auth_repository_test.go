package usecase_test

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	"golang.org/x/crypto/bcrypt"
	"sstu-go-forum-auth-service/internal/model"
	"sstu-go-forum-auth-service/internal/repository/mocks"
	"sstu-go-forum-auth-service/internal/usecase"
	"sstu-go-forum-auth-service/internal/utils"
	"testing"
	"time"
)

func TestRegister_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRepo := mocks.NewMockAuthRepository(ctrl)
	uc := usecase.NewAuthUseCase(mockRepo)
	user := &model.User{Username: "user", Password: "password", Role: "USER"}
	mockRepo.EXPECT().GetUserByUsername("user").Return(nil, nil)
	mockRepo.EXPECT().CreateUser(user).DoAndReturn(func(u *model.User) error { u.ID = 1; return nil })
	resp, err := uc.Register(user)
	assert.NoError(t, err)
	assert.Equal(t, 1, resp.UserID)
}

func TestRegister_ExistingUser(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRepo := mocks.NewMockAuthRepository(ctrl)
	uc := usecase.NewAuthUseCase(mockRepo)
	user := &model.User{Username: "user", Password: "password", Role: "USER"}
	mockRepo.EXPECT().GetUserByUsername("user").Return(&model.User{}, nil)
	_, err := uc.Register(user)
	assert.Error(t, err)
}

func TestLogin_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRepo := mocks.NewMockAuthRepository(ctrl)
	hash, _ := bcrypt.GenerateFromPassword([]byte("p"), bcrypt.DefaultCost)
	mockRepo.EXPECT().GetUserByUsername("u").Return(&model.User{ID: 1, Username: "u", Password: string(hash), Role: "r"}, nil)
	mockRepo.EXPECT().DeleteRefreshTokensByUserID(1).Return(nil)
	mockRepo.EXPECT().SaveRefreshToken(gomock.Any()).Return(nil)
	uc := usecase.NewAuthUseCase(mockRepo)
	resp, err := uc.Login(model.LoginRequest{Username: "u", Password: "p"})
	assert.NoError(t, err)
	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken)
}

func TestLogin_InvalidCredentials(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRepo := mocks.NewMockAuthRepository(ctrl)
	mockRepo.EXPECT().GetUserByUsername("u").Return(nil, errors.New("not found"))
	uc := usecase.NewAuthUseCase(mockRepo)
	_, err := uc.Login(model.LoginRequest{Username: "u", Password: "p"})
	assert.Error(t, err)
}

func TestRefreshToken_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRepo := mocks.NewMockAuthRepository(ctrl)
	token, exp, _ := utils.GenerateRefreshToken(1, "u", "r")
	mockRepo.EXPECT().GetRefreshToken(token).Return(&model.RefreshToken{UserID: 1, Token: token, ExpiresAt: exp}, nil)
	mockRepo.EXPECT().DeleteRefreshToken(token).Return(nil)
	mockRepo.EXPECT().SaveRefreshToken(gomock.Any()).Return(nil)
	uc := usecase.NewAuthUseCase(mockRepo)
	resp, err := uc.RefreshToken(model.RefreshRequest{RefreshToken: token})
	assert.NoError(t, err)
	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken)
}

func TestRefreshToken_Expired(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockRepo := mocks.NewMockAuthRepository(ctrl)
	token, _, _ := utils.GenerateRefreshToken(1, "u", "r")
	mockRepo.EXPECT().GetRefreshToken(token).Return(&model.RefreshToken{UserID: 1, Token: token, ExpiresAt: time.Now().Add(-time.Hour)}, nil)
	uc := usecase.NewAuthUseCase(mockRepo)
	_, err := uc.RefreshToken(model.RefreshRequest{RefreshToken: token})
	assert.Error(t, err)
}
