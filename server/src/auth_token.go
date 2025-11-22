package main

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

const (
	authTokenBytes = 32
	authTokenTTL   = 7 * 24 * time.Hour
)

type AuthTokenInfo struct {
	Token     string
	ExpiresAt time.Time
}

func generateAuthToken() (string, error) {
	buf := make([]byte, authTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func getOrCreateAuthToken(userID int) (AuthTokenInfo, error) {
	var info AuthTokenInfo

	token, expiresAt, err := models.Users.GetAuthToken(userID)
	if err == nil && token.Valid && expiresAt.Valid && expiresAt.Time.After(time.Now()) {
		return AuthTokenInfo{
			Token:     token.String,
			ExpiresAt: expiresAt.Time,
		}, nil
	}

	newToken, err := generateAuthToken()
	if err != nil {
		return info, err
	}
	expires := time.Now().Add(authTokenTTL)

	if err := models.Users.SetAuthToken(userID, newToken, expires); err != nil {
		return info, err
	}

	info.Token = newToken
	info.ExpiresAt = expires
	return info, nil
}

func getUsernameForAuthToken(token string) (string, int, error) {
	return models.Users.GetUsernameByAuthToken(token)
}
