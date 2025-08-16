package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type Client struct {
	db *sql.DB
}

func NewClient(dbURL string) (Client, error) {
	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		return Client{}, err
	}
	// Pool settings (tune as needed)
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		return Client{}, err
	}

	c := Client{db: db}
	if err := c.autoMigrate(); err != nil {
		_ = db.Close()
		return Client{}, err
	}
	return c, nil
}

func (c Client) Close() error {
	return c.db.Close()
}

func (c Client) Ping(ctx context.Context) error {
	return c.db.PingContext(ctx)
}

func (c *Client) autoMigrate() error {
	if _, err := c.db.Exec(
		`CREATE EXTENSION IF NOT EXISTS pgcrypto`,
	); err != nil {
		return fmt.Errorf("failed to enable pgcrypto: %w", err)
	}

	userTable := `
	CREATE TABLE IF NOT EXISTS users (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		email TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL
	);
	`
	if _, err := c.db.Exec(userTable); err != nil {
		return fmt.Errorf("failed to create users table: %w", err)
	}

	refreshTokenTable := `
	CREATE TABLE IF NOT EXISTS refresh_tokens (
		token TEXT PRIMARY KEY,
		user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		expires_at TIMESTAMPTZ NOT NULL,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		revoked_at TIMESTAMPTZ
	);
	CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id);
	CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
	`
	if _, err := c.db.Exec(refreshTokenTable); err != nil {
		return fmt.Errorf("failed to create refresh_tokens table: %w", err)
	}

	return nil
}

func (c Client) Reset() error {
	_, err := c.db.Exec(
		"TRUNCATE TABLE refresh_tokens, users RESTART IDENTITY CASCADE",
	)
	if err != nil {
		return fmt.Errorf("failed to reset tables: %w", err)
	}
	return nil
}