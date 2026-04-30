package auth

import (
	"context"
	"crypto/rand"
	"encoding/gob"
	"encoding/hex"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/sessions"
)

func init() {
	gob.Register([]string{})
}

const sessionName = "pds-pro"

type sessionUserKey struct{}

type SessionUser struct {
	Subject  string
	Email    string
	Name     string
	Provider string
	Roles    []string
	IssuedAt time.Time
}

type Manager struct {
	store    *sessions.CookieStore
	secure   bool
	maxAge   int
}

func NewManager(secretFile string, secure bool, maxAgeSec int) (*Manager, error) {
	secret, err := loadOrCreateSecret(secretFile)
	if err != nil {
		return nil, err
	}
	store := sessions.NewCookieStore(secret)
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   maxAgeSec,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}
	return &Manager{store: store, secure: secure, maxAge: maxAgeSec}, nil
}

func (m *Manager) Save(w http.ResponseWriter, r *http.Request, u SessionUser) error {
	s, _ := m.store.Get(r, sessionName)
	s.Values["sub"] = u.Subject
	s.Values["email"] = u.Email
	s.Values["name"] = u.Name
	s.Values["provider"] = u.Provider
	s.Values["roles"] = u.Roles
	s.Values["issued_at"] = u.IssuedAt.Unix()
	return s.Save(r, w)
}

func (m *Manager) Get(r *http.Request) (*SessionUser, bool) {
	s, _ := m.store.Get(r, sessionName)
	sub, _ := s.Values["sub"].(string)
	if sub == "" {
		return nil, false
	}
	email, _ := s.Values["email"].(string)
	name, _ := s.Values["name"].(string)
	provider, _ := s.Values["provider"].(string)
	roles, _ := s.Values["roles"].([]string)
	issued, _ := s.Values["issued_at"].(int64)
	return &SessionUser{
		Subject:  sub,
		Email:    email,
		Name:     name,
		Provider: provider,
		Roles:    roles,
		IssuedAt: time.Unix(issued, 0),
	}, true
}

func (m *Manager) Clear(w http.ResponseWriter, r *http.Request) error {
	s, _ := m.store.Get(r, sessionName)
	s.Options.MaxAge = -1
	return s.Save(r, w)
}

func (m *Manager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, ok := m.Get(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		ctx := context.WithValue(r.Context(), sessionUserKey{}, u)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func UserFromContext(ctx context.Context) *SessionUser {
	u, _ := ctx.Value(sessionUserKey{}).(*SessionUser)
	return u
}

func loadOrCreateSecret(path string) ([]byte, error) {
	if path == "" {
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return nil, err
		}
		return secret, nil
	}
	if b, err := os.ReadFile(path); err == nil {
		decoded, err := hex.DecodeString(string(trimNewline(b)))
		if err != nil {
			return nil, err
		}
		if len(decoded) < 32 {
			return nil, os.ErrInvalid
		}
		return decoded, nil
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(secret)+"\n"), 0o600); err != nil {
		return nil, err
	}
	return secret, nil
}

func trimNewline(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

