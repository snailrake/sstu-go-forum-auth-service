package postgres

import (
	"database/sql"
	"sstu-go-forum-auth-service/internal/domain"
	_ "time"
)

type Repository struct {
	DB *sql.DB
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{DB: db}
}

func (r *Repository) CreateUser(user *domain.User) error {
	return r.DB.QueryRow(
		"INSERT INTO users (username, password, role) VALUES ($1, $2, $3) RETURNING id",
		user.Username, user.Password, user.Role,
	).Scan(&user.ID)
}

func (r *Repository) GetUserByUsername(username string) (*domain.User, error) {
	user := &domain.User{}
	err := r.DB.QueryRow(
		"SELECT id, username, password, role FROM users WHERE username=$1",
		username,
	).Scan(&user.ID, &user.Username, &user.Password, &user.Role)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (r *Repository) DeleteRefreshTokensByUserID(userID int) error {
	_, err := r.DB.Exec("DELETE FROM refresh_tokens WHERE user_id = $1", userID)
	return err
}

func (r *Repository) SaveRefreshToken(token *domain.RefreshToken) error {
	return r.DB.QueryRow(
		"INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1, $2, $3) RETURNING id",
		token.UserID, token.Token, token.ExpiresAt,
	).Scan(&token.ID)
}

func (r *Repository) GetRefreshToken(tokenString string) (*domain.RefreshToken, error) {
	rt := &domain.RefreshToken{}
	err := r.DB.QueryRow(
		"SELECT id, user_id, token, expires_at FROM refresh_tokens WHERE token = $1",
		tokenString,
	).Scan(&rt.ID, &rt.UserID, &rt.Token, &rt.ExpiresAt)
	if err != nil {
		return nil, err
	}
	return rt, nil
}

func (r *Repository) DeleteRefreshToken(tokenString string) error {
	_, err := r.DB.Exec("DELETE FROM refresh_tokens WHERE token = $1", tokenString)
	return err
}
