package auth

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestGenerateSessionID(t *testing.T) {
	id1 := GenerateSessionID()
	id2 := GenerateSessionID()

	if id1 == "" {
		t.Error("GenerateSessionID returned an empty string")
	}
	if id1 == id2 {
		t.Error("GenerateSessionID returned the same ID twice")
	}
}

func TestCreateSession(t *testing.T) {
	username := "testuser"
	sessionID := CreateSession(username)

	if sessionID == "" {
		t.Fatal("CreateSession returned an empty session ID")
	}

	mutex.RLock()
	data, ok := sessions[sessionID]
	mutex.RUnlock()

	if !ok {
		t.Errorf("Session %s not found in sessions map", sessionID)
	}
	if data.Username != username {
		t.Errorf("Expected username %s, got %s", username, data.Username)
	}
	if data.ExpiresAt.Before(time.Now()) {
		t.Error("Session created with an expired timestamp")
	}
}

func TestGetSession(t *testing.T) {
	username := "testuser"
	sessionID := CreateSession(username)

	t.Run("Valid session", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{Name: "session_id", Value: sessionID})

		gotUser, ok := GetSession(req)
		if !ok {
			t.Error("GetSession failed to retrieve a valid session")
		}
		if gotUser != username {
			t.Errorf("Expected username %s, got %s", username, gotUser)
		}
	})

	t.Run("Missing cookie", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		_, ok := GetSession(req)
		if ok {
			t.Error("GetSession returned ok for missing cookie")
		}
	})

	t.Run("Non-existent session ID", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{Name: "session_id", Value: "nonexistent"})
		_, ok := GetSession(req)
		if ok {
			t.Error("GetSession returned ok for non-existent session ID")
		}
	})

	t.Run("Expired session", func(t *testing.T) {
		expiredID := "expired-id"
		mutex.Lock()
		sessions[expiredID] = SessionData{
			Username:  username,
			ExpiresAt: time.Now().Add(-1 * time.Hour),
		}
		mutex.Unlock()

		req := httptest.NewRequest("GET", "/", nil)
		req.AddCookie(&http.Cookie{Name: "session_id", Value: expiredID})

		_, ok := GetSession(req)
		if ok {
			t.Error("GetSession returned ok for expired session")
		}

		mutex.RLock()
		_, exists := sessions[expiredID]
		mutex.RUnlock()
		if exists {
			t.Error("Expired session was not deleted from sessions map")
		}
	})
}

func TestDestroySession(t *testing.T) {
	username := "testuser"
	sessionID := CreateSession(username)

	req := httptest.NewRequest("POST", "/logout", nil)
	req.AddCookie(&http.Cookie{Name: "session_id", Value: sessionID})
	w := httptest.NewRecorder()

	DestroySession(w, req)

	mutex.RLock()
	_, ok := sessions[sessionID]
	mutex.RUnlock()

	if ok {
		t.Error("Session still exists in map after DestroySession")
	}

	resp := w.Result()
	cookies := resp.Cookies()
	var found bool
	for _, c := range cookies {
		if c.Name == "session_id" {
			found = true
			if c.Value != "" {
				t.Errorf("Expected empty cookie value, got %s", c.Value)
			}
			// Expires is set to Unix(0, 0), which means it's definitely in the past.
			if !c.Expires.Before(time.Now()) {
				t.Errorf("Expected expired cookie, got expiry %v", c.Expires)
			}
			break
		}
	}
	if !found {
		t.Error("Session cookie not cleared in response")
	}
}

func TestSetSessionCookie(t *testing.T) {
	sessionID := "test-session-id"
	w := httptest.NewRecorder()
	SetSessionCookie(w, sessionID)

	resp := w.Result()
	cookies := resp.Cookies()
	var found bool
	for _, c := range cookies {
		if c.Name == "session_id" {
			found = true
			if c.Value != sessionID {
				t.Errorf("Expected cookie value %s, got %s", sessionID, c.Value)
			}
			if !c.HttpOnly {
				t.Error("Cookie should be HttpOnly")
			}
			if !c.Secure {
				t.Error("Cookie should be Secure")
			}
			if c.SameSite != http.SameSiteStrictMode {
				t.Error("Cookie should have SameSiteStrictMode")
			}
			break
		}
	}
	if !found {
		t.Error("Session cookie not set in response")
	}
}

func TestDestroySession_NoCookie(t *testing.T) {
	req := httptest.NewRequest("POST", "/logout", nil)
	w := httptest.NewRecorder()

	DestroySession(w, req)

	resp := w.Result()
	cookies := resp.Cookies()
	for _, c := range cookies {
		if c.Name == "session_id" {
			t.Error("Session cookie should not be set when no cookie was present in request")
		}
	}
}

func TestConcurrentSessions(t *testing.T) {
	const numGoroutines = 100
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(i int) {
			defer wg.Done()
			username := "user"
			sessionID := CreateSession(username)

			req := httptest.NewRequest("GET", "/", nil)
			req.AddCookie(&http.Cookie{Name: "session_id", Value: sessionID})

			gotUser, ok := GetSession(req)
			if !ok || gotUser != username {
				t.Errorf("Concurrent session failed for user %d", i)
			}

			w := httptest.NewRecorder()
			DestroySession(w, req)
		}(i)
	}
	wg.Wait()
}

func TestCreateSessionPrunesExpired(t *testing.T) {
	staleID := "stale-id"
	mutex.Lock()
	sessions[staleID] = SessionData{Username: "old", ExpiresAt: time.Now().Add(-time.Minute)}
	mutex.Unlock()

	CreateSession("someone")

	mutex.RLock()
	_, exists := sessions[staleID]
	mutex.RUnlock()
	if exists {
		t.Error("expired session was not pruned on CreateSession")
	}
}

func TestDestroyOtherSessions(t *testing.T) {
	current := CreateSession("rotator")
	other := CreateSession("rotator")
	unrelated := CreateSession("bystander")

	req := httptest.NewRequest("POST", "/change_password", nil)
	req.AddCookie(&http.Cookie{Name: "session_id", Value: current})
	DestroyOtherSessions(req, "rotator")

	mutex.RLock()
	_, hasCurrent := sessions[current]
	_, hasOther := sessions[other]
	_, hasUnrelated := sessions[unrelated]
	mutex.RUnlock()

	if !hasCurrent {
		t.Error("current session should be kept")
	}
	if hasOther {
		t.Error("other session of the same user should be destroyed")
	}
	if !hasUnrelated {
		t.Error("sessions of other users should be kept")
	}
}

func sessionRequest(id string) *http.Request {
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: "session_id", Value: id})
	return req
}

func assertDone(t *testing.T, ctx interface{ Done() <-chan struct{} }, what string) {
	t.Helper()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Errorf("session context not cancelled after %s", what)
	}
}

func TestSessionContext_CancelledOnLogout(t *testing.T) {
	id := CreateSession("streamer")
	ctx, ok := SessionContext(sessionRequest(id))
	if !ok {
		t.Fatal("expected a session context")
	}
	if ctx.Err() != nil {
		t.Fatal("context of a live session must not be cancelled")
	}
	DestroySession(httptest.NewRecorder(), sessionRequest(id))
	assertDone(t, ctx, "logout")
}

func TestSessionContext_CancelledOnRevocation(t *testing.T) {
	current := CreateSession("revoked")
	other := CreateSession("revoked")
	ctx, ok := SessionContext(sessionRequest(other))
	if !ok {
		t.Fatal("expected a session context")
	}
	DestroyOtherSessions(sessionRequest(current), "revoked")
	assertDone(t, ctx, "password-change revocation")

	if _, ok := SessionContext(sessionRequest(other)); ok {
		t.Error("revoked session must not yield a context")
	}
}

func TestSessionContext_ExpiresWithSession(t *testing.T) {
	id := "legacy-injected"
	mutex.Lock()
	sessions[id] = SessionData{Username: "short", ExpiresAt: time.Now().Add(50 * time.Millisecond)}
	mutex.Unlock()

	ctx, ok := SessionContext(sessionRequest(id))
	if !ok {
		t.Fatal("expected a session context")
	}
	assertDone(t, ctx, "expiry")
}

func TestCreateSessionIfCurrent_RejectsAfterPasswordChange(t *testing.T) {
	gen := CredentialGeneration("racer")
	keeper := CreateSession("racer")

	// A password change commits while the login is still verifying.
	DestroyOtherSessions(sessionRequest(keeper), "racer")

	if id, ok := CreateSessionIfCurrent("racer", gen); ok || id != "" {
		t.Fatal("login that verified a retired password must not create a session")
	}
	if _, ok := CreateSessionIfCurrent("racer", CredentialGeneration("racer")); !ok {
		t.Error("login with the current generation should succeed")
	}
}
