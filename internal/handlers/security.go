package handlers

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

var trustedProxyPrefixes []netip.Prefix

func ConfigureTrustedProxies(raw string) error {
	prefixes := make([]netip.Prefix, 0)
	for _, value := range strings.Split(raw, ",") {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return fmt.Errorf("parse trusted proxy CIDR %q: %w", value, err)
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	trustedProxyPrefixes = prefixes
	return nil
}

func isSecureRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	remote, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	trusted := false
	for _, prefix := range trustedProxyPrefixes {
		if prefix.Contains(remote) {
			trusted = true
			break
		}
	}
	if !trusted {
		return false
	}
	values := r.Header.Values("X-Forwarded-Proto")
	return len(values) == 1 && strings.EqualFold(strings.TrimSpace(values[0]), "https")
}

func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'")
		if isSecureRequest(r) {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}
