package handlers

import (
	"net/http"

	"github.com/arumes31/servworx/internal/auth"
	"github.com/arumes31/servworx/internal/config"
)

// requireAuth is a middleware to enforce authentication
func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, ok := auth.GetSession(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Ensure admin has changed default password
		if username == "admin" && r.URL.Path != "/change_password" && r.URL.Path != "/logout" {
			cfg, err := config.LoadConfig()
			if err == nil {
				if checkPassword("changeme", cfg.Users["admin"]) {
					http.Redirect(w, r, "/change_password", http.StatusSeeOther)
					return
				}
			}
		}

		next(w, r)
	}
}
