package admin

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAdminSessionProtectsAPI(t *testing.T) {
	file := filepath.Join(t.TempDir(), "password")
	const password = "local-test-password-123"
	if err := os.WriteFile(file, []byte(password+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	gate, err := New("admin", file, true, true)
	if err != nil {
		t.Fatal(err)
	}
	handler := gate.Protect(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	request := func(method, path, body, origin string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "https://sentinel.example"+path, strings.NewReader(body))
		if body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	if got := request("GET", "/api/servers", "", "", nil).Code; got != http.StatusUnauthorized {
		t.Fatalf("unauthenticated API status = %d", got)
	}
	login := `{"username":"admin","password":"` + password + `"}`
	if got := request("POST", "/api/auth/login", login, "https://other.example", nil).Code; got != http.StatusForbidden {
		t.Fatalf("cross-origin login status = %d", got)
	}
	w := request("POST", "/api/auth/login", login, "https://sentinel.example", nil)
	cookies := w.Result().Cookies()
	if w.Code != http.StatusOK || len(cookies) != 1 {
		t.Fatalf("login status = %d, cookies = %d", w.Code, len(cookies))
	}
	cookie := cookies[0]
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("unexpected session cookie flags")
	}
	if got := request("GET", "/api/servers", "", "", cookie).Code; got != http.StatusNoContent {
		t.Fatalf("authenticated API status = %d", got)
	}
	if got := request("POST", "/api/auth/logout", "", "https://sentinel.example", cookie).Code; got != http.StatusNoContent {
		t.Fatalf("logout status = %d", got)
	}
	if got := request("GET", "/api/servers", "", "", cookie).Code; got != http.StatusUnauthorized {
		t.Fatalf("revoked session status = %d", got)
	}
}

func TestOfficeModeFailsClosed(t *testing.T) {
	if _, err := New("admin", "", true, false); err == nil {
		t.Fatal("expected office mode to require a password file")
	}
}
