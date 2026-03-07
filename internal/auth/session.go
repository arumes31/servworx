package auth

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"sync"
	"time"
)

var (
	sessions = make(map[string]SessionData)
	mutex    sync.RWMutex
)

type SessionData struct {
	Username  string
	ExpiresAt time.Time
}

func GenerateSessionID() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func CreateSession(username string) string {
	sessionID := GenerateSessionID()
	mutex.Lock()
	defer mutex.Unlock()
	sessions[sessionID] = SessionData{
		Username:  username,
		ExpiresAt: time.Now().Add(24 * time.Hour), // 24 hour session
	}
	return sessionID
}

func GetSession(r *http.Request) (string, bool) {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return "", false
	}
	sessionID := cookie.Value

	mutex.RLock()
	defer mutex.RUnlock()
	data, ok := sessions[sessionID]
	if !ok {
		return "", false
	}
	if time.Now().After(data.ExpiresAt) {
		return "", false
	}
	return data.Username, true
}

func DestroySession(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return
	}
	sessionID := cookie.Value

	mutex.Lock()
	defer mutex.Unlock()
	delete(sessions, sessionID)

	// Clear cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
	})
}

func SetSessionCookie(w http.ResponseWriter, sessionID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Path:     "/",
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode, // Improved security
	})
}
