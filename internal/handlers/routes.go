package handlers

import (
	"fmt"
	"net/http"

	"github.com/arumes31/servworx/internal/auth"
)

func RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if _, ok := auth.GetSession(r); !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/config", http.StatusSeeOther)
	})

	mux.HandleFunc("GET /login", HandleLoginGET)
	mux.HandleFunc("POST /login", HandleLoginPOST)
	mux.HandleFunc("GET /logout", requireAuth(HandleLogout))
	mux.HandleFunc("GET /change_password", requireAuth(HandleChangePasswordGET))
	mux.HandleFunc("POST /change_password", requireAuth(HandleChangePasswordPOST))
	mux.HandleFunc("GET /config", requireAuth(HandleConfigGET))
	mux.HandleFunc("POST /update_service/{index}", requireAuth(HandleUpdateServicePOST))
	mux.HandleFunc("POST /add_service", requireAuth(HandleAddServicePOST))
	mux.HandleFunc("POST /force_restart/{index}", requireAuth(HandleForceRestartPOST))
	mux.HandleFunc("POST /pause_monitoring/{index}", requireAuth(HandlePauseMonitoringPOST))
	mux.HandleFunc("GET /view_logs/{index}", requireAuth(HandleViewLogsGET))

	// JSON / AJAX UX Endpoints
	mux.HandleFunc("GET /api/status", requireAuth(HandleAPIStatusGET))
	mux.HandleFunc("GET /api/logs/stream/{index}", requireAuth(HandleAPILogsStreamGET))
	mux.HandleFunc("POST /api/notifications/test", requireAuth(HandleAPINotificationTestPOST))
	mux.HandleFunc("POST /api/snooze/{index}", requireAuth(HandleAPISnoozePOST))

	// Favicon Route serving our premium animated SVG
	mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		fmt.Fprint(w, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">
  <defs>
    <filter id="glow">
      <feGaussianBlur stdDeviation="2.5" result="coloredBlur"/>
      <feMerge>
        <feMergeNode in="coloredBlur"/>
        <feMergeNode in="SourceGraphic"/>
      </feMerge>
    </filter>
    <linearGradient id="starGradient" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" style="stop-color:#00F2FF;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#FF00E5;stop-opacity:1" />
    </linearGradient>
  </defs>
  <!-- Main Star -->
  <path d="M50 5 L58 42 L95 50 L58 58 L50 95 L42 58 L5 50 L42 42 Z" fill="url(#starGradient)" filter="url(#glow)">
    <animateTransform attributeName="transform" type="rotate" from="0 50 50" to="360 50 50" dur="20s" repeatCount="indefinite" />
  </path>
  <!-- Secondary Points -->
  <path d="M50 25 L54 46 L75 50 L54 54 L50 75 L46 54 L25 50 L46 46 Z" fill="#FFFFFF" opacity="0.6" filter="url(#glow)">
    <animateTransform attributeName="transform" type="rotate" from="360 50 50" to="0 50 50" dur="15s" repeatCount="indefinite" />
  </path>
</svg>`)
	})

	// Static Assets Route
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
}
