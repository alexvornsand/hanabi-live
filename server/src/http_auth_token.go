package main

import (
	"errors"
	"net/http"
	"time"

	"github.com/Hanabi-Live/hanabi-live/logger"
	gsessions "github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v4"
	"go.uber.org/zap"
)

func httpAuthToken(c *gin.Context) {
	errorRef := c.GetHeader("X-Error-Ref")
	session := gsessions.Default(c)
	userIDRaw := session.Get("userID")
	userID, ok := userIDRaw.(int)
	if !ok {
		if errorRef != "" {
			logger.Warn(
				"auth token request unauthorized",
				zap.Any("userIDRaw", userIDRaw),
				zap.String("errorRef", errorRef),
			)
		}
		c.String(http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized))
		return
	}

	info, err := getOrCreateAuthToken(userID)
	if err != nil {
		logger.Error(
			"Failed to get or create auth token",
			zap.Error(err),
			zap.String("errorRef", errorRef),
			zap.Int("userID", userID),
		)
		c.String(http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
		return
	}

	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{
		"token":     info.Token,
		"expiresAt": info.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

func httpAuthUsername(c *gin.Context) {
	errorRef := c.GetHeader("X-Error-Ref")
	token := c.Query("token")
	if token == "" {
		if errorRef != "" {
			logger.Warn("auth username request missing token", zap.String("errorRef", errorRef))
		}
		c.String(http.StatusBadRequest, http.StatusText(http.StatusBadRequest))
		return
	}

	username, _, err := getUsernameForAuthToken(token)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			if errorRef != "" {
				logger.Warn("auth username not found for token", zap.String("errorRef", errorRef))
			}
			c.String(http.StatusNotFound, http.StatusText(http.StatusNotFound))
			return
		}

		logger.Error(
			"Failed to lookup username by auth token",
			zap.Error(err),
			zap.String("errorRef", errorRef),
		)
		c.String(http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError))
		return
	}

	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{
		"username": username,
	})
}
