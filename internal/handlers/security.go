package handlers

import (
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"
)

// trustedProxies returns the networks that may set X-Forwarded-* headers.
// It is configured with TRUSTED_PROXIES (comma separated IPs, CIDRs or the
// keywords "loopback" and "private"). When unset, only loopback peers are
// trusted: a reverse proxy on a Docker network or another host must be listed
// explicitly, so clients that can reach the port directly cannot spoof their
// address or the request scheme. Any invalid entry makes the whole setting
// fail closed (no proxy is trusted).
var trustedProxies = sync.OnceValue(func() []netip.Prefix {
	raw, set := os.LookupEnv("TRUSTED_PROXIES")
	if !set || strings.TrimSpace(raw) == "" {
		raw = "loopback"
	}
	return parseTrustedProxies(raw)
})

var proxyKeywords = map[string][]string{
	"loopback": {"127.0.0.0/8", "::1/128"},
	"private":  {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"},
}

// parseTrustedProxies parses a TRUSTED_PROXIES value. It returns nil if any
// entry is invalid, so a typo never widens trust.
func parseTrustedProxies(raw string) []netip.Prefix {
	var prefixes []netip.Prefix
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if cidrs, ok := proxyKeywords[strings.ToLower(entry)]; ok {
			for _, c := range cidrs {
				prefixes = append(prefixes, netip.MustParsePrefix(c))
			}
			continue
		}
		if p, err := netip.ParsePrefix(entry); err == nil {
			prefixes = append(prefixes, p.Masked())
			continue
		}
		if a, err := netip.ParseAddr(entry); err == nil {
			a = a.Unmap()
			prefixes = append(prefixes, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		// #nosec G706 -- operator-supplied env value, quoted with %q
		log.Printf("Invalid TRUSTED_PROXIES entry %q: ignoring X-Forwarded-* headers from all peers until it is fixed", entry)
		return nil
	}
	return prefixes
}

func parseIP(s string) (netip.Addr, bool) {
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

func isTrustedAddr(a netip.Addr, prefixes []netip.Prefix) bool {
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func isTrustedProxy(remoteAddr string) bool {
	a, ok := parseIP(remoteAddr)
	return ok && isTrustedAddr(a, trustedProxies())
}

var untrustedProxyHint sync.Once

// isSecureRequest reports whether the request reached us over HTTPS, either
// directly or through a trusted reverse proxy.
func isSecureRequest(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	https := strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	if !https {
		return false
	}
	if isTrustedProxy(r.RemoteAddr) {
		return true
	}
	untrustedProxyHint.Do(func() {
		// #nosec G706 -- peer address is parsed by net/http, quoted with %q
		log.Printf("Ignoring X-Forwarded-Proto from untrusted peer %q; if this is your reverse proxy, add it to TRUSTED_PROXIES", r.RemoteAddr)
	})
	return false
}

// clientIP returns the address of the client, honouring X-Forwarded-For only
// when the direct peer is a trusted proxy.
func clientIP(r *http.Request) string {
	remote, ok := parseIP(r.RemoteAddr)
	if !ok {
		return r.RemoteAddr
	}
	prefixes := trustedProxies()
	if !isTrustedAddr(remote, prefixes) {
		return remote.String()
	}
	// Walk X-Forwarded-For from the right and return the first untrusted hop.
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		a, ok := parseIP(hops[i])
		if !ok {
			continue
		}
		if !isTrustedAddr(a, prefixes) {
			return a.String()
		}
		remote = a
	}
	return remote.String()
}

// securityHeaders adds basic hardening headers to every response. The pages use
// inline scripts and styles, so the CSP only restricts framing, plugins, the
// base URL and form targets.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		next.ServeHTTP(w, r)
	})
}

// Protect wraps the router with security headers and cross-origin request
// protection. State-changing requests (POST etc.) are rejected unless the
// browser marks them as same-origin (Sec-Fetch-Site) or the Origin header
// matches the Host, which blocks CSRF from other sites, including sibling
// subdomains.
func Protect(next http.Handler) http.Handler {
	return securityHeaders(http.NewCrossOriginProtection().Handler(next))
}

// Login throttling settings.
const (
	loginMaxFailuresPerIP   = 5
	loginMaxFailuresPerUser = 10
	loginFailureWindow      = 15 * time.Minute
	loginBaseLockout        = time.Minute
	loginMaxLockout         = 30 * time.Minute
)

type loginAttempts struct {
	failures    int
	lastFailure time.Time
	lockedUntil time.Time
}

// loginLimiter tracks failed logins per key and locks the key out with an
// exponentially growing delay once the failure limit is reached.
type loginLimiter struct {
	mu          sync.Mutex
	maxFailures int
	entries     map[string]*loginAttempts
}

func newLoginLimiter(maxFailures int) *loginLimiter {
	return &loginLimiter{maxFailures: maxFailures, entries: make(map[string]*loginAttempts)}
}

var (
	ipLoginLimiter   = newLoginLimiter(loginMaxFailuresPerIP)
	userLoginLimiter = newLoginLimiter(loginMaxFailuresPerUser)
)

// lockedFor returns how long the key is still locked out.
func (l *loginLimiter) lockedFor(key string, now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e, ok := l.entries[key]; ok && now.Before(e.lockedUntil) {
		return e.lockedUntil.Sub(now)
	}
	return 0
}

// fail records a failed attempt and returns true if the key is now locked.
func (l *loginLimiter) fail(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	for k, e := range l.entries {
		if now.Sub(e.lastFailure) > loginFailureWindow && now.After(e.lockedUntil) {
			delete(l.entries, k)
		}
	}

	e, ok := l.entries[key]
	if !ok {
		e = &loginAttempts{}
		l.entries[key] = e
	}
	e.failures++
	e.lastFailure = now

	if e.failures < l.maxFailures {
		return false
	}
	lockout := loginMaxLockout
	if shift := e.failures - l.maxFailures; shift < 6 {
		lockout = min(loginBaseLockout<<shift, loginMaxLockout)
	}
	e.lockedUntil = now.Add(lockout)
	return true
}

func (l *loginLimiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

// resetLoginLimiters clears all login throttling state (used by tests).
func resetLoginLimiters() {
	for _, l := range []*loginLimiter{ipLoginLimiter, userLoginLimiter} {
		l.mu.Lock()
		l.entries = make(map[string]*loginAttempts)
		l.mu.Unlock()
	}
}
