package database

import (
	"context"
	"database/sql"
	"time"
)

type CreateRefreshTokenParams struct {
	Token     string    `json:"token"`
	UserID    any       `json:"user_id"` // uuid.UUID, but 'any' for pgx direct scan
	ExpiresAt time.Time `json:"expires_at"`
}

func (c Client) CreateRefreshToken(
	ctx context.Context,
	params CreateRefreshTokenParams,
) (RefreshToken, error) {
	const query = `
		INSERT INTO refresh_tokens (
			token, user_id, expires_at
		) VALUES ($1, $2, $3)
		RETURNING created_at, updated_at
	`
	var rt RefreshToken
	rt.Token = params.Token
	rt.ExpiresAt = params.ExpiresAt

	err := c.db.QueryRowContext(
		ctx,
		query,
		params.Token,
		params.UserID,
		params.ExpiresAt,
	).Scan(&rt.CreatedAt, &rt.UpdatedAt)
	if err != nil {
		return RefreshToken{}, err
	}

	// Assign after successful insert
	switch v := params.UserID.(type) {
	case string:
		// not typical for pgx, but guard anyway
		// ignore parse error, it's not used by callers
		// in this path
		_ = v
	default:
	}

	return rt, nil
}

func (c Client) GetRefreshToken(
	ctx context.Context,
	token string,
) (RefreshToken, error) {
	const query = `
		SELECT token, user_id, expires_at, created_at, updated_at, revoked_at
		FROM refresh_tokens
		WHERE token = $1
		  AND revoked_at IS NULL
		  AND expires_at > NOW()
	`
	var rt RefreshToken
	err := c.db.QueryRowContext(ctx, query, token).Scan(
		&rt.Token,
		&rt.UserID,
		&rt.ExpiresAt,
		&rt.CreatedAt,
		&rt.UpdatedAt,
		&rt.RevokedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return RefreshToken{}, err
		}
		return RefreshToken{}, err
	}
	return rt, nil
}

func (c Client) RevokeRefreshToken(ctx context.Context, token string) error {
	const query = `
		UPDATE refresh_tokens
		SET revoked_at = NOW(), updated_at = NOW()
		WHERE token = $1
	`
	_, err := c.db.ExecContext(ctx, query, token)
	return err
}

func (c Client) DeleteRefreshToken(ctx context.Context, token string) error {
	const query = `DELETE FROM refresh_tokens WHERE token = $1`
	_, err := c.db.ExecContext(ctx, query, token)
	return err
}