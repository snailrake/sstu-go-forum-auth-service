package impl

import (
	"database/sql"

	"sstu-go-forum-auth-service/internal/model"
)

type AuthRepositoryImpl struct {
	DB *sql.DB
}

func NewRepository(db *sql.DB) *AuthRepositoryImpl {
	return &AuthRepositoryImpl{DB: db}
}

func (r *AuthRepositoryImpl) CreateUser(user *model.User) error {
	return r.DB.QueryRow(
		"INSERT INTO users (username, password, role) VALUES ($1, $2, $3) RETURNING id",
		user.Username, user.Password, user.Role,
	).Scan(&user.ID)
}

func (r *AuthRepositoryImpl) GetUserByUsername(username string) (*model.User, error) {
	user := &model.User{}
	err := r.DB.QueryRow(
		"SELECT id, username, password, role FROM users WHERE username = $1",
		username,
	).Scan(&user.ID, &user.Username, &user.Password, &user.Role)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (r *AuthRepositoryImpl) DeleteRefreshTokensByUserID(userID int) error {
	_, err := r.DB.Exec("DELETE FROM refresh_tokens WHERE user_id = $1", userID)
	return err
}

func (r *AuthRepositoryImpl) SaveRefreshToken(token *model.RefreshToken) error {
	return r.DB.QueryRow(
		"INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1, $2, $3) RETURNING id",
		token.UserID, token.Token, token.ExpiresAt,
	).Scan(&token.ID)
}

func (r *AuthRepositoryImpl) GetRefreshToken(tokenString string) (*model.RefreshToken, error) {
	rt := &model.RefreshToken{}
	err := r.DB.QueryRow(
		"SELECT id, user_id, token, expires_at FROM refresh_tokens WHERE token = $1",
		tokenString,
	).Scan(&rt.ID, &rt.UserID, &rt.Token, &rt.ExpiresAt)
	if err != nil {
		return nil, err
	}
	return rt, nil
}

func (r *AuthRepositoryImpl) DeleteRefreshToken(tokenString string) error {
	_, err := r.DB.Exec("DELETE FROM refresh_tokens WHERE token = $1", tokenString)
	return err
}
