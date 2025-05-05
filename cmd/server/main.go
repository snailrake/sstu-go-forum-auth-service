// cmd/server/main.go
package main

import (
	"database/sql"
	"fmt"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"log"
	"net/http"
	"os"
	"sstu-go-forum-auth-service/internal/handler"
	"sstu-go-forum-auth-service/internal/repository/postgres"
	"sstu-go-forum-auth-service/internal/usecase"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Fatal("ошибка загрузки .env")
	}

	// Подключаемся к базе данных
	dbURL := os.Getenv("DATABASE_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Connected to database")

	// Инициализация репозиториев и use case
	authRepo := postgres.NewRepository(db)
	authUC := usecase.NewAuthUseCase(authRepo)
	authHandler := handler.NewAuthHandler(authUC)

	// Настройка маршрутов
	mux := http.NewServeMux()
	mux.HandleFunc("/register", authHandler.Register)
	mux.HandleFunc("/login", authHandler.Login)
	mux.HandleFunc("/refresh", authHandler.Refresh)

	// Запуск сервера
	fmt.Println("Server is running on :8080")
	log.Fatal(http.ListenAndServe(":8081", withCORS(mux)))
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
