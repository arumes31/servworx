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
	_, _ = rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func CreateSession(username string) string {
	sessionID := GenerateSessionID()
	mutex.Lock()
	defer mutex.Unlock()
	pruneExpiredLocked(time.Now())
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
	data, ok := sessions[sessionID]
	mutex.RUnlock()

	if !ok {
		return "", false
	}

	if time.Now().After(data.ExpiresAt) {
		mutex.Lock()
		delete(sessions, sessionID)
		mutex.Unlock()
		return "", false
	}

	return data.Username, true
}

// pruneExpiredLocked removes expired sessions so the map does not grow with
// every login. The caller must hold mutex.
func pruneExpiredLocked(now time.Time) {
	for id, data := range sessions {
		if now.After(data.ExpiresAt) {
			delete(sessions, id)
		}
	}
}

// DestroyOtherSessions removes every session of username except the one used
// by the current request, e.g. after a password change.
func DestroyOtherSessions(r *http.Request, username string) {
	currentID := ""
	if cookie, err := r.Cookie("session_id"); err == nil {
		currentID = cookie.Value
	}

	mutex.Lock()
	defer mutex.Unlock()
	for id, data := range sessions {
		if data.Username == username && id != currentID {
			delete(sessions, id)
		}
	}
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
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

func SetSessionCookie(w http.ResponseWriter, sessionID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Path:     "/",
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode, // Improved security
	})
}
