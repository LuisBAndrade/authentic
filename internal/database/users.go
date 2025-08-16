package database

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"
)

var ErrNotFound = errors.New("not found")

func (c Client) GetUserByEmail(ctx context.Context, email string) (User, error) {
	const query = `
		SELECT id, created_at, updated_at, email, password
		FROM users
		WHERE email = $1
	`
	var u User
	err := c.db.QueryRowContext(ctx, query, email).Scan(
		&u.ID,
		&u.CreatedAt,
		&u.UpdatedAt,
		&u.Email,
		&u.Password,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, ErrNotFound
		}
		return User{}, err
	}
	return u, nil
}

func (c Client) GetUser(ctx context.Context, id uuid.UUID) (*User, error) {
	const query = `
		SELECT id, created_at, updated_at, email, password
		FROM users
		WHERE id = $1
	`
	var u User
	err := c.db.QueryRowContext(ctx, query, id).Scan(
		&u.ID,
		&u.CreatedAt,
		&u.UpdatedAt,
		&u.Email,
		&u.Password,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &u, nil
}

func (c Client) CreateUser(
	ctx context.Context,
	params CreateUserParams,
) (*User, error) {
	const query = `
		INSERT INTO users (email, password)
		VALUES ($1, $2)
		RETURNING id, created_at, updated_at
	`
	var u User
	u.Email = params.Email
	u.Password = params.Password

	err := c.db.QueryRowContext(ctx, query, params.Email, params.Password).
		Scan(&u.ID, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (c Client) DeleteUser(ctx context.Context, id uuid.UUID) error {
	const query = `DELETE FROM users WHERE id = $1`
	_, err := c.db.ExecContext(ctx, query, id)
	return err
}

func (c Client) GetUserByRefreshToken(
	ctx context.Context,
	token string,
) (*User, error) {
	const query = `
		SELECT
			u.id,
			u.email,
			u.created_at,
			u.updated_at,
			u.password
		FROM users u
		JOIN refresh_tokens rt ON u.id = rt.user_id
		WHERE rt.token = $1
		  AND rt.revoked_at IS NULL
		  AND rt.expires_at > NOW()
	`
	var u User
	err := c.db.QueryRowContext(ctx, query, token).Scan(
		&u.ID,
		&u.Email,
		&u.CreatedAt,
		&u.UpdatedAt,
		&u.Password,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &u, nil
}