package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/LuisBAndrade/go-testing-app/internal/database"
	"github.com/joho/godotenv"
)

type apiConfig struct {
	db        database.Client
	jwtSecret string
	port      string
}

func main() {
	_ = godotenv.Load(".env")

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("DATABASE_URL must be set")
	}
	dbURL = ensureSSLModeRequire(dbURL)

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatal("JWT_SECRET must be set")
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
		log.Println("PORT not set, defaulting to 8080")
	}

	db, err := database.NewClient(dbURL)
	if err != nil {
		log.Fatalf("couldn't connect to database: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Printf("error closing db: %v", err)
		}
	}()

	cfg := apiConfig{
		db:        db,
		jwtSecret: jwtSecret,
		port:      port,
	}

	mux := http.NewServeMux()
	// Auth routes
	mux.HandleFunc("POST /api/register", cfg.handlerRegister)
	mux.HandleFunc("POST /api/login", cfg.handlerLogin)
	mux.HandleFunc("POST /api/refresh", cfg.handlerRefresh)
	mux.HandleFunc("POST /api/logout", cfg.handlerLogout)
	mux.Handle("GET /api/me", cfg.requireAuth(http.HandlerFunc(cfg.handlerMe)))

	// Health check (includes DB ping)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 1*time.Second)
		defer cancel()
		if err := cfg.db.Ping(ctx); err != nil {
			respondWithJSON(w, http.StatusServiceUnavailable, map[string]any{
				"status": "degraded",
				"db":     "down",
			})
			return
		}
		respondWithJSON(w, http.StatusOK, map[string]any{
			"status": "ok",
			"db":     "up",
		})
	})

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           withCORS(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Start server
	go func() {
		log.Printf("Server starting on port %s", port)
		if err := srv.ListenAndServe(); err != nil &&
			err != http.ErrServerClosed {
			log.Fatalf("server failed: %v", err)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("server forced to shutdown: %v", err)
	}
	log.Println("Server exited")
}

func ensureSSLModeRequire(dbURL string) string {
	if strings.Contains(dbURL, "sslmode=") {
		return dbURL
	}
	sep := "?"
	if strings.Contains(dbURL, "?") {
		sep = "&"
	}
	return dbURL + sep + "sslmode=require"
}