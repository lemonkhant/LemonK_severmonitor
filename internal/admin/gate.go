package admin

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const cookieName = "sentinel_session"
const sessionTTL = 12 * time.Hour

type Gate struct {
	username string
	password [sha256.Size]byte
	required bool
	secure   bool
	mu       sync.Mutex
	sessions map[string]time.Time
	failed   int
	retryAt  time.Time
}

// New configures the single office administrator. An empty file path keeps local development open.
func New(username, file string, required, secure bool) (*Gate, error) {
	g := &Gate{required: file != "", secure: secure, username: username, sessions: make(map[string]time.Time)}
	if file == "" {
		if required {
			return nil, errors.New("office mode requires SENTINEL_ADMIN_PASSWORD_FILE")
		}
		return g, nil
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	password := strings.TrimRight(string(raw), "\r\n")
	if username == "" || len(password) < 16 || len(password) > 1024 {
		return nil, errors.New("set an admin username and a password of 16–1024 bytes")
	}
	g.password = sha256.Sum256([]byte(password))
	return g, nil
}

func (g *Gate) Enabled() bool { return g.required }

func (g *Gate) Protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/auth/session":
			send(w, http.StatusOK, map[string]bool{"required": g.required, "signedIn": g.signedIn(r)})
		case r.Method == http.MethodPost && r.URL.Path == "/api/auth/login":
			g.login(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/api/auth/logout":
			g.logout(w, r)
		case !g.signedIn(r):
			send(w, http.StatusUnauthorized, map[string]string{"error": "Sign in to lemonK."})
		case r.Method != http.MethodGet && r.Method != http.MethodHead && !sameOrigin(r):
			send(w, http.StatusForbidden, map[string]string{"error": "Cross-origin changes are disabled."})
		default:
			next.ServeHTTP(w, r)
		}
	})
}

func (g *Gate) signedIn(r *http.Request) bool {
	if !g.required {
		return true
	}
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	expires, ok := g.sessions[cookie.Value]
	if ok && !time.Now().Before(expires) {
		delete(g.sessions, cookie.Value)
		return false
	}
	return ok
}

func (g *Gate) login(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		send(w, http.StatusForbidden, map[string]string{"error": "Cross-origin sign-in is disabled."})
		return
	}
	if !g.required {
		send(w, http.StatusOK, map[string]bool{"signedIn": true})
		return
	}
	if media, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); media != "application/json" {
		send(w, http.StatusUnsupportedMediaType, map[string]string{"error": "Expected a JSON request."})
		return
	}
	var credentials struct {
		Username string
		Password string
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&credentials); err != nil || decoder.Decode(new(any)) != io.EOF {
		send(w, http.StatusBadRequest, map[string]string{"error": "Invalid sign-in request."})
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	if now.Before(g.retryAt) {
		w.Header().Set("Retry-After", "60")
		send(w, http.StatusTooManyRequests, map[string]string{"error": "Too many sign-in attempts. Try again in a minute."})
		return
	}
	digest := sha256.Sum256([]byte(credentials.Password))
	if subtle.ConstantTimeCompare(digest[:], g.password[:]) != 1 || credentials.Username != g.username {
		g.failed++
		if g.failed >= 8 {
			g.failed = 0
			g.retryAt = now.Add(time.Minute)
		}
		send(w, http.StatusUnauthorized, map[string]string{"error": "Incorrect username or password."})
		return
	}
	g.failed = 0
	for token, expiry := range g.sessions {
		if !now.Before(expiry) {
			delete(g.sessions, token)
		}
	}
	if len(g.sessions) >= 64 {
		send(w, http.StatusServiceUnavailable, map[string]string{"error": "Too many active sessions. Sign out of another session."})
		return
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		send(w, http.StatusInternalServerError, map[string]string{"error": "Could not start a session."})
		return
	}
	token := hex.EncodeToString(secret[:])
	g.sessions[token] = now.Add(sessionTTL)
	http.SetCookie(w, g.cookie(r, token, int(sessionTTL/time.Second)))
	send(w, http.StatusOK, map[string]bool{"signedIn": true})
}

func (g *Gate) logout(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		send(w, http.StatusForbidden, map[string]string{"error": "Cross-origin sign-out is disabled."})
		return
	}
	if cookie, err := r.Cookie(cookieName); err == nil {
		g.mu.Lock()
		delete(g.sessions, cookie.Value)
		g.mu.Unlock()
	}
	http.SetCookie(w, g.cookie(r, "", -1))
	w.WriteHeader(http.StatusNoContent)
}

func (g *Gate) cookie(r *http.Request, token string, maxAge int) *http.Cookie {
	return &http.Cookie{Name: cookieName, Value: token, Path: "/", MaxAge: maxAge, HttpOnly: true, Secure: g.secure || r.TLS != nil, SameSite: http.SameSiteStrictMode}
}

func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return r.Header.Get("Sec-Fetch-Site") != "cross-site"
	}
	u, err := url.Parse(origin)
	return err == nil && u.Host == r.Host && (u.Scheme == "http" || u.Scheme == "https")
}

func send(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
