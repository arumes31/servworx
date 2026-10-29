package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"sync"
	"time"
)

// SessionLifetime is how long a session stays valid after login.
const SessionLifetime = 24 * time.Hour

var (
	sessions = make(map[string]SessionData)
	mutex    sync.RWMutex

	// generations counts credential changes per user. A login records the
	// generation before it verifies the password and only creates a session if
	// no password change happened in the meantime.
	generations = make(map[string]uint64)
)

type SessionData struct {
	Username  string
	ExpiresAt time.Time

	// ctx is cancelled when the session expires or is revoked, so long-lived
	// requests (e.g. log streams) can stop once their authorization ends.
	ctx    context.Context
	cancel context.CancelFunc
}

func (d SessionData) revoke() {
	if d.cancel != nil {
		d.cancel()
	}
}

func GenerateSessionID() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func CreateSession(username string) string {
	sessionID, _ := CreateSessionIfCurrent(username, CredentialGeneration(username))
	return sessionID
}

// CredentialGeneration returns the current credential generation of username.
// Pass it to CreateSessionIfCurrent after verifying the password.
func CredentialGeneration(username string) uint64 {
	mutex.RLock()
	defer mutex.RUnlock()
	return generations[username]
}

// CreateSessionIfCurrent creates a session unless the credentials of username
// changed since generation was read. This prevents a login that verified a
// just-retired password from outliving the revocation of a password change.
func CreateSessionIfCurrent(username string, generation uint64) (string, bool) {
	sessionID := GenerateSessionID()
	now := time.Now()
	expiresAt := now.Add(SessionLifetime)
	ctx, cancel := context.WithDeadline(context.Background(), expiresAt)

	mutex.Lock()
	defer mutex.Unlock()
	if generations[username] != generation {
		cancel()
		return "", false
	}
	pruneExpiredLocked(now)
	sessions[sessionID] = SessionData{
		Username:  username,
		ExpiresAt: expiresAt,
		ctx:       ctx,
		cancel:    cancel,
	}
	return sessionID, true
}

func lookupSession(r *http.Request) (SessionData, bool) {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return SessionData{}, false
	}
	sessionID := cookie.Value

	mutex.RLock()
	data, ok := sessions[sessionID]
	mutex.RUnlock()

	if !ok {
		return SessionData{}, false
	}

	if time.Now().After(data.ExpiresAt) {
		mutex.Lock()
		delete(sessions, sessionID)
		mutex.Unlock()
		data.revoke()
		return SessionData{}, false
	}

	return data, true
}

func GetSession(r *http.Request) (string, bool) {
	data, ok := lookupSession(r)
	return data.Username, ok
}

// SessionContext returns a context that is cancelled when the session of the
// request expires, is logged out or is revoked by a password change.
func SessionContext(r *http.Request) (context.Context, bool) {
	data, ok := lookupSession(r)
	if !ok {
		return nil, false
	}
	if data.ctx != nil {
		return data.ctx, true
	}

	// Sessions inserted without a context (e.g. by tests) get one lazily.
	cookie, _ := r.Cookie("session_id")
	mutex.Lock()
	defer mutex.Unlock()
	current, ok := sessions[cookie.Value]
	if !ok {
		return nil, false
	}
	if current.ctx == nil {
		current.ctx, current.cancel = context.WithDeadline(context.Background(), current.ExpiresAt)
		sessions[cookie.Value] = current
	}
	return current.ctx, true
}

// pruneExpiredLocked removes expired sessions so the map does not grow with
// every login. The caller must hold mutex.
func pruneExpiredLocked(now time.Time) {
	for id, data := range sessions {
		if now.After(data.ExpiresAt) {
			delete(sessions, id)
			data.revoke()
		}
	}
}

// DestroyOtherSessions removes every session of username except the one used
// by the current request, e.g. after a password change. It also advances the
// credential generation so logins that verified the old password in parallel
// cannot create a new session afterwards.
func DestroyOtherSessions(r *http.Request, username string) {
	currentID := ""
	if cookie, err := r.Cookie("session_id"); err == nil {
		currentID = cookie.Value
	}

	mutex.Lock()
	defer mutex.Unlock()
	generations[username]++
	for id, data := range sessions {
		if data.Username == username && id != currentID {
			delete(sessions, id)
			data.revoke()
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
	if data, ok := sessions[sessionID]; ok {
		delete(sessions, sessionID)
		data.revoke()
	}

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
		Expires:  time.Now().Add(SessionLifetime),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode, // Improved security
	})
}
