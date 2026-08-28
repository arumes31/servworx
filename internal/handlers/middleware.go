package handlers

import (
	"net/http"

	"github.com/arumes31/servworx/internal/auth"
)

// requireAuth is a middleware to enforce authentication
func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, ok := auth.GetSession(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		next(w, r)
	}
}
