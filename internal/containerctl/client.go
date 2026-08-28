package containerctl

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const maxErrorBody = 4 << 10

var ErrUnavailable = errors.New("container control is unavailable")

type Controller interface {
	Restart(context.Context, string) error
	Logs(context.Context, string, int, bool) (io.ReadCloser, error)
}

type UnavailableController struct{}

func (UnavailableController) Restart(context.Context, string) error {
	return ErrUnavailable
}

func (UnavailableController) Logs(context.Context, string, int, bool) (io.ReadCloser, error) {
	return nil, ErrUnavailable
}

type Client struct {
	baseURL *url.URL
	token   string
	http    *http.Client
}

func New(rawURL, token string) (*Client, error) {
	baseURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse broker URL: %w", err)
	}
	if baseURL.Scheme != "http" && baseURL.Scheme != "https" {
		return nil, errors.New("broker URL must use http or https")
	}
	if baseURL.Host == "" || baseURL.User != nil || baseURL.RawQuery != "" || baseURL.Fragment != "" {
		return nil, errors.New("broker URL must be a complete origin without credentials, query, or fragment")
	}
	baseURL.Path = strings.TrimRight(baseURL.Path, "/")
	if len(token) < 32 || strings.TrimSpace(token) != token {
		return nil, errors.New("broker token must contain at least 32 non-whitespace characters")
	}

	return &Client{
		baseURL: baseURL,
		token:   token,
		http: &http.Client{
			Timeout: 35 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func NewFromEnvironment() (*Client, error) {
	token, err := ReadSecret(os.Getenv("CONTAINER_BROKER_TOKEN_FILE"), os.Getenv("CONTAINER_BROKER_TOKEN"))
	if err != nil {
		return nil, err
	}
	rawURL := os.Getenv("CONTAINER_BROKER_URL")
	if rawURL == "" {
		return nil, errors.New("CONTAINER_BROKER_URL is required")
	}
	return New(rawURL, token)
}

func ReadSecret(filename, fallback string) (string, error) {
	secret := fallback
	if filename != "" {
		// #nosec G304 G703 -- startup-only path supplied by the deployment operator, never by an HTTP request.
		data, err := os.ReadFile(filename)
		if err != nil {
			return "", fmt.Errorf("read broker token file: %w", err)
		}
		secret = strings.TrimSpace(string(data))
	}
	if len(secret) < 32 || strings.TrimSpace(secret) != secret {
		return "", errors.New("container broker token must contain at least 32 non-whitespace characters")
	}
	return secret, nil
}

func (c *Client) Restart(ctx context.Context, name string) error {
	resp, err := c.do(ctx, http.MethodPost, name, "restart", nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		return responseError(resp)
	}
	return nil
}

func (c *Client) Logs(ctx context.Context, name string, tail int, follow bool) (io.ReadCloser, error) {
	query := url.Values{}
	query.Set("tail", strconv.Itoa(tail))
	query.Set("follow", strconv.FormatBool(follow))
	resp, err := c.do(ctx, http.MethodGet, name, "logs", query)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		err := responseError(resp)
		_ = resp.Body.Close()
		return nil, err
	}
	return resp.Body, nil
}

func (c *Client) do(ctx context.Context, method, name, action string, query url.Values) (*http.Response, error) {
	if !validContainerName(name) {
		return nil, errors.New("invalid container name")
	}
	u := *c.baseURL
	u.Path = strings.TrimRight(c.baseURL.Path, "/") + "/v1/containers/" + url.PathEscape(name) + "/" + action
	u.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("create broker request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("container broker request: %w", err)
	}
	return resp, nil
}

func responseError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	message := strings.TrimSpace(string(body))
	if message == "" {
		message = http.StatusText(resp.StatusCode)
	}
	return fmt.Errorf("container broker returned %d: %s", resp.StatusCode, message)
}

func Authorized(header, token string) bool {
	provided := strings.TrimPrefix(header, "Bearer ")
	if provided == header || len(provided) != len(token) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(token)) == 1
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
