package auth

import (
	"net/http"
	"net/http/httptest"
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
