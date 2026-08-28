package broker

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/arumes31/servworx/internal/containerctl"
)

const maxDockerError = 4 << 10

type Server struct {
	token   string
	allowed map[string]struct{}
	docker  *http.Client
}

func New(token, socketPath string, allowed []string) (*Server, error) {
	if len(token) < 32 || strings.TrimSpace(token) != token {
		return nil, errors.New("broker token must contain at least 32 non-whitespace characters")
	}
	if socketPath == "" {
		return nil, errors.New("docker socket path is required")
	}
	allowset := make(map[string]struct{}, len(allowed))
	for _, name := range allowed {
		name = strings.TrimSpace(name)
		if !validContainerName(name) {
			return nil, fmt.Errorf("invalid allowed container name %q", name)
		}
		allowset[name] = struct{}{}
	}
	if len(allowset) == 0 {
		return nil, errors.New("at least one allowed container is required")
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialer := net.Dialer{Timeout: 5 * time.Second}
			return dialer.DialContext(ctx, "unix", socketPath)
		},
		DisableCompression: true,
	}
	return &Server{
		token:   token,
		allowed: allowset,
		docker:  &http.Client{Transport: transport, Timeout: 0},
	}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("POST /v1/containers/{name}/restart", s.restart)
	mux.HandleFunc("GET /v1/containers/{name}/logs", s.logs)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.URL.Path != "/healthz" && !containerctl.Authorized(r.Header.Get("Authorization"), s.token) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (s *Server) restart(w http.ResponseWriter, r *http.Request) {
	name, ok := s.authorizeName(w, r.PathValue("name"))
	if !ok {
		return
	}
	endpoint := "http://docker/containers/" + url.PathEscape(name) + "/restart?t=30"
	// #nosec G704 -- the host is constant, the transport dials only the configured Unix socket, and name is validated and allowlisted.
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, endpoint, nil)
	if err != nil {
		http.Error(w, "could not create Docker request", http.StatusInternalServerError)
		return
	}
	// #nosec G704 -- the client transport cannot dial IP networks and the request target is constructed above.
	resp, err := s.docker.Do(req)
	if err != nil {
		http.Error(w, "Docker restart failed", http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		copyDockerError(w, resp)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) logs(w http.ResponseWriter, r *http.Request) {
	name, ok := s.authorizeName(w, r.PathValue("name"))
	if !ok {
		return
	}
	tail, err := strconv.Atoi(r.URL.Query().Get("tail"))
	if err != nil || tail < 1 || tail > 500 {
		http.Error(w, "tail must be between 1 and 500", http.StatusBadRequest)
		return
	}
	follow, err := strconv.ParseBool(r.URL.Query().Get("follow"))
	if err != nil {
		http.Error(w, "follow must be true or false", http.StatusBadRequest)
		return
	}
	query := url.Values{
		"stdout": {"1"},
		"stderr": {"1"},
		"tail":   {strconv.Itoa(tail)},
		"follow": {strconv.FormatBool(follow)},
	}
	endpoint := "http://docker/containers/" + url.PathEscape(name) + "/logs?" + query.Encode()
	// #nosec G704 -- the host is constant, the transport dials only the configured Unix socket, and name/query are bounded.
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, endpoint, nil)
	if err != nil {
		http.Error(w, "could not create Docker request", http.StatusInternalServerError)
		return
	}
	// #nosec G704 -- the client transport cannot dial IP networks and the request target is constructed above.
	resp, err := s.docker.Do(req)
	if err != nil {
		http.Error(w, "Docker logs failed", http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		copyDockerError(w, resp)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if strings.Contains(resp.Header.Get("Content-Type"), "application/vnd.docker.raw-stream") {
		_ = copyDockerFrames(w, resp.Body)
		return
	}
	_, _ = io.Copy(w, resp.Body)
}

func (s *Server) authorizeName(w http.ResponseWriter, name string) (string, bool) {
	if !validContainerName(name) {
		http.Error(w, "invalid container name", http.StatusBadRequest)
		return "", false
	}
	if _, ok := s.allowed[name]; !ok {
		http.Error(w, "container is not allowlisted", http.StatusForbidden)
		return "", false
	}
	return name, true
}

func copyDockerError(w http.ResponseWriter, resp *http.Response) {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxDockerError))
	message := strings.TrimSpace(string(body))
	if message == "" {
		message = http.StatusText(resp.StatusCode)
	}
	http.Error(w, message, resp.StatusCode)
}

func copyDockerFrames(dst io.Writer, src io.Reader) error {
	reader := bufio.NewReader(src)
	header := make([]byte, 8)
	for {
		if _, err := io.ReadFull(reader, header); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return err
		}
		length := binary.BigEndian.Uint32(header[4:])
		if length > 1<<20 {
			return errors.New("docker log frame exceeds 1 MiB")
		}
		if _, err := io.CopyN(dst, reader, int64(length)); err != nil {
			return err
		}
	}
}

func validContainerName(name string) bool {
	if name == "" || strings.HasPrefix(name, "-") {
		return false
	}
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '.' || r == '-' {
			continue
		}
		return false
	}
	return true
}
