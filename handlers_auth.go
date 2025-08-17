package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/LuisBAndrade/go-testing-app/internal/auth"
	"github.com/LuisBAndrade/go-testing-app/internal/database"
)

type userResponse struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func toUserResponse(u database.User) userResponse {
	return userResponse{
		ID:        u.ID.String(),
		Email:     u.Email,
		CreatedAt: u.CreatedAt,
		UpdatedAt: u.UpdatedAt,
	}
}

// POST /api/register
func (cfg *apiConfig) handlerRegister(w http.ResponseWriter, r *http.Request) {
	type params struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	var p params
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid JSON body", err)
		return
	}

	p.Email = strings.TrimSpace(strings.ToLower(p.Email))
	if p.Email == "" || len(p.Password) < 8 {
		respondWithError(
			w,
			http.StatusBadRequest,
			"invalid email or password too short",
			nil,
		)
		return
	}

	// Check if user exists
	_, err := cfg.db.GetUserByEmail(r.Context(), p.Email)
	if err == nil {
		respondWithError(w, http.StatusConflict, "email already registered", nil)
		return
	}
	if !errors.Is(err, database.ErrNotFound) && err != nil {
		respondWithError(w, http.StatusInternalServerError, "lookup failed", err)
		return
	}

	hashed, err := auth.HashPassword(p.Password)
	if err != nil {
		respondWithError(
			w,
			http.StatusInternalServerError,
			"couldn't hash password",
			err,
		)
		return
	}

	u, err := cfg.db.CreateUser(r.Context(), database.CreateUserParams{
		Email:    p.Email,
		Password: hashed,
	})
	if err != nil {
		respondWithError(
			w,
			http.StatusInternalServerError,
			"couldn't create user",
			err,
		)
		return
	}

	respondWithJSON(w, http.StatusCreated, toUserResponse(*u))
}

// POST /api/login
func (cfg *apiConfig) handlerLogin(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}
	type response struct {
		User         userResponse `json:"user"`
		Token        string       `json:"token"`
		RefreshToken string       `json:"refresh_token"`
	}

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var params parameters
	if err := dec.Decode(&params); err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid JSON body", err)
		return
	}
	params.Email = strings.TrimSpace(strings.ToLower(params.Email))

	user, err := cfg.db.GetUserByEmail(r.Context(), params.Email)
	if err != nil {
		respondWithError(
			w,
			http.StatusUnauthorized,
			"incorrect email or password",
			err,
		)
		return
	}

	if err := auth.CheckPasswordHash(params.Password, user.Password); err != nil {
		respondWithError(
			w,
			http.StatusUnauthorized,
			"incorrect email or password",
			err,
		)
		return
	}

	accessToken, err := auth.MakeJWT(
		user.ID,
		cfg.jwtSecret,
		15*time.Minute,
	)
	if err != nil {
		respondWithError(
			w,
			http.StatusInternalServerError,
			"couldn't create access JWT",
			err,
		)
		return
	}

	refreshToken, err := auth.MakeRefreshToken()
	if err != nil {
		respondWithError(
			w,
			http.StatusInternalServerError,
			"couldn't create refresh token",
			err,
		)
		return
	}

	if _, err := cfg.db.CreateRefreshToken(
		r.Context(),
		database.CreateRefreshTokenParams{
			UserID:    user.ID,
			Token:     refreshToken,
			ExpiresAt: time.Now().UTC().Add(60 * 24 * time.Hour),
		},
	); err != nil {
		respondWithError(
			w,
			http.StatusInternalServerError,
			"couldn't save refresh token",
			err,
		)
		return
	}

	respondWithJSON(w, http.StatusOK, response{
		User:         toUserResponse(user),
		Token:        accessToken,
		RefreshToken: refreshToken,
	})
}

// POST /api/refresh
func (cfg *apiConfig) handlerRefresh(w http.ResponseWriter, r *http.Request) {
	type params struct {
		RefreshToken string `json:"refresh_token"`
	}
	type resp struct {
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
	}

	var p params
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid JSON body", err)
		return
	}
	if p.RefreshToken == "" {
		respondWithError(w, http.StatusBadRequest, "refresh_token required", nil)
		return
	}

	rt, err := cfg.db.GetRefreshToken(r.Context(), p.RefreshToken)
	if err != nil {
		respondWithError(
			w,
			http.StatusUnauthorized,
			"invalid refresh token",
			err,
		)
		return
	}

	u, err := cfg.db.GetUser(r.Context(), rt.UserID)
	if err != nil || u == nil {
		respondWithError(
			w,
			http.StatusUnauthorized,
			"user not found for token",
			err,
		)
		return
	}

	accessToken, err := auth.MakeJWT(u.ID, cfg.jwtSecret, 15*time.Minute)
	if err != nil {
		respondWithError(
			w,
			http.StatusInternalServerError,
			"couldn't create access JWT",
			err,
		)
		return
	}

	newRT, err := auth.MakeRefreshToken()
	if err != nil {
		respondWithError(
			w,
			http.StatusInternalServerError,
			"couldn't create refresh token",
			err,
		)
		return
	}

	if _, err := cfg.db.CreateRefreshToken(
		r.Context(),
		database.CreateRefreshTokenParams{
			UserID:    u.ID,
			Token:     newRT,
			ExpiresAt: time.Now().UTC().Add(60 * 24 * time.Hour),
		},
	); err != nil {
		respondWithError(
			w,
			http.StatusInternalServerError,
			"couldn't persist new refresh token",
			err,
		)
		return
	}
	_ = cfg.db.RevokeRefreshToken(r.Context(), rt.Token)

	respondWithJSON(w, http.StatusOK, resp{
		Token:        accessToken,
		RefreshToken: newRT,
	})
}

// POST /api/logout
func (cfg *apiConfig) handlerLogout(w http.ResponseWriter, r *http.Request) {
	type params struct {
		RefreshToken string `json:"refresh_token"`
	}
	var p params
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		respondWithError(w, http.StatusBadRequest, "invalid JSON body", err)
		return
	}
	if p.RefreshToken == "" {
		respondWithError(w, http.StatusBadRequest, "refresh_token required", nil)
		return
	}
	if err := cfg.db.RevokeRefreshToken(r.Context(), p.RefreshToken); err != nil {
		respondWithError(
			w,
			http.StatusInternalServerError,
			"couldn't revoke refresh token",
			err,
		)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GET /api/me
func (cfg *apiConfig) handlerMe(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFromCtx(r.Context())
	if !ok {
		respondWithError(
			w,
			http.StatusUnauthorized,
			"missing auth context",
			errors.New("no user id"),
		)
		return
	}
	u, err := cfg.db.GetUser(r.Context(), userID)
	if err != nil || u == nil {
		respondWithError(w, http.StatusUnauthorized, "user not found", err)
		return
	}
	respondWithJSON(w, http.StatusOK, toUserResponse(*u))
}