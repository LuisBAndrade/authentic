package main

import (
	"encoding/json"
	"log"
	"net/http"
)

type errorEnvelope struct {
	Error string `json:"error"`
}

func respondWithJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if payload == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("write json failed: %v", err)
	}
}

func respondWithError(w http.ResponseWriter, status int, msg string, err error) {
	if err != nil {
		log.Printf("%s: %v", msg, err)
	}
	respondWithJSON(w, status, errorEnvelope{Error: msg})
}