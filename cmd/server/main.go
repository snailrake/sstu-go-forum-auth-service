package main

import (
	"database/sql"
	"log"
	"net/http"
	"os"
	"sstu-go-forum-auth-service/internal/repository/impl"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/rs/zerolog"
	httpSwagger "github.com/swaggo/http-swagger"

	_ "sstu-go-forum-auth-service/docs"
	"sstu-go-forum-auth-service/internal/handler"
	"sstu-go-forum-auth-service/internal/usecase"
)

var logger zerolog.Logger

func init() {
	logger = zerolog.New(os.Stdout).With().Timestamp().Logger()
}

// @title API сервиса авторизации
// @version 1.0
// @host localhost:8081
// @BasePath /
// @schemes http
func main() {
	if err := godotenv.Load(); err != nil {
		logger.Fatal().Err(err).Msg("failed to load .env")
	}

	db, err := sql.Open("postgres", os.Getenv("DATABASE_URL"))
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to open database connection")
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		logger.Fatal().Err(err).Msg("failed to ping database")
	}

	authUC := usecase.NewAuthUseCase(impl.NewRepository(db))
	authHandler := handler.NewAuthHandler(authUC)

	mux := http.NewServeMux()
	mux.HandleFunc("/register", authHandler.Register)
	mux.HandleFunc("/login", authHandler.Login)
	mux.HandleFunc("/refresh", authHandler.Refresh)
	mux.HandleFunc("/swagger/", httpSwagger.WrapHandler)

	logger.Info().Msg("Starting server on :8081")
	log.Fatal(http.ListenAndServe(":8081", withCORS(mux)))
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logger.Debug().Str("method", r.Method).Str("url", r.URL.String()).Msg("handling request")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}
