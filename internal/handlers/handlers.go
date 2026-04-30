package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	htmltemplate "html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/P3X-118/pds-pro/internal/audit"
	"github.com/P3X-118/pds-pro/internal/auth"
	"github.com/P3X-118/pds-pro/internal/config"
	"github.com/P3X-118/pds-pro/internal/goat"
	"github.com/go-chi/chi/v5"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
)

type Templates map[string]*htmltemplate.Template

type Server struct {
	cfg       *config.Config
	tpl       Templates
	sessions  *auth.Manager
	audit     *audit.Logger
	providers []string
}

func New(cfg *config.Config, tpl Templates, sm *auth.Manager, al *audit.Logger, providers []string) *Server {
	return &Server{cfg: cfg, tpl: tpl, sessions: sm, audit: al, providers: providers}
}

func (s *Server) Routes() http.Handler {
	r := chi.NewRouter()

	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })

	r.Get("/login", s.login)
	r.Get("/auth/{provider}", s.authStart)
	r.Get("/auth/{provider}/callback", s.authCallback)
	r.Post("/logout", s.logout)

	r.Group(func(r chi.Router) {
		r.Use(s.sessions.Middleware)
		r.Get("/", s.home)
		r.Get("/instances/{instance}/accounts", s.accountList)
		r.Get("/instances/{instance}/accounts/new", s.accountNewForm)
		r.Post("/instances/{instance}/accounts", s.accountCreate)
		r.Get("/instances/{instance}/accounts/{user}", s.accountInfo)
		r.Post("/instances/{instance}/accounts/{user}/takedown", s.accountTakedown)
		r.Post("/instances/{instance}/accounts/{user}/reset-password", s.accountResetPassword)
		r.Post("/instances/{instance}/accounts/{user}/delete", s.accountDelete)
		r.Post("/instances/{instance}/accounts/{user}/update", s.accountUpdate)
		r.Get("/instances/{instance}/invites", s.invitesForm)
		r.Post("/instances/{instance}/invites", s.invitesCreate)
		r.Get("/instances/{instance}/blob", s.blobForm)
		r.Post("/instances/{instance}/blob/purge", s.blobPurge)
		r.Get("/instances/{instance}/crawl", s.crawlForm)
		r.Post("/instances/{instance}/crawl", s.crawlRequest)
	})

	return r
}

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	t, ok := s.tpl[name]
	if !ok {
		http.Error(w, "template not found: "+name, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, "layout.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	s.render(w, "login.html", map[string]any{"Providers": s.providers})
}

func (s *Server) authStart(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")
	q := r.URL.Query()
	q.Set("provider", provider)
	r.URL.RawQuery = q.Encode()
	gothic.BeginAuthHandler(w, r)
}

func (s *Server) authCallback(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")
	q := r.URL.Query()
	q.Set("provider", provider)
	r.URL.RawQuery = q.Encode()

	gu, err := gothic.CompleteUserAuth(w, r)
	if err != nil {
		http.Error(w, "auth failed: "+err.Error(), http.StatusUnauthorized)
		return
	}

	subject := fmt.Sprintf("%s|%s", provider, gu.UserID)
	decision := auth.Authorize(s.cfg.Allowlist, subject, gu.Email)
	if !decision.Allowed {
		s.audit.Log(audit.Entry{
			Subject: subject, Email: gu.Email, Provider: provider,
			Action: "login.denied", Result: "denied",
			Args: map[string]string{"name": fullName(gu)},
		})
		http.Error(w, "not authorized", http.StatusForbidden)
		return
	}

	if err := s.sessions.Save(w, r, auth.SessionUser{
		Subject:  subject,
		Email:    gu.Email,
		Name:     fullName(gu),
		Provider: provider,
		Roles:    decision.Roles,
		IssuedAt: time.Now().UTC(),
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.audit.Log(audit.Entry{
		Subject: subject, Email: gu.Email, Provider: provider,
		Action: "login", Result: "ok",
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if u, ok := s.sessions.Get(r); ok {
		s.audit.Log(audit.Entry{Subject: u.Subject, Email: u.Email, Provider: u.Provider, Action: "logout", Result: "ok"})
	}
	_ = s.sessions.Clear(w, r)
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	s.render(w, "home.html", map[string]any{
		"User":      u,
		"Instances": s.cfg.Instances,
	})
}

func (s *Server) accountList(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	instName := chi.URLParam(r, "instance")
	inst := s.cfg.Instance(instName)
	if inst == nil {
		http.NotFound(w, r)
		return
	}
	cli, err := goat.NewClient(s.cfg.Goat.BinaryPath, inst)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	accounts, err := cli.AccountList(r.Context())
	result := "ok"
	errMsg := ""
	if err != nil {
		result = "error"
		errMsg = err.Error()
	}
	s.audit.Log(audit.Entry{
		Subject: u.Subject, Email: u.Email, Provider: u.Provider,
		Instance: instName, Action: "account.list", Result: result, Error: errMsg,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	s.render(w, "accounts.html", map[string]any{
		"User":     u,
		"Instance": inst,
		"Accounts": accounts,
	})
}

func (s *Server) accountNewForm(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	instName := chi.URLParam(r, "instance")
	inst := s.cfg.Instance(instName)
	if inst == nil {
		http.NotFound(w, r)
		return
	}
	s.render(w, "account_new.html", map[string]any{"User": u, "Instance": inst})
}

func (s *Server) accountCreate(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if !auth.HasRole(u.Roles, "super-admin") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	instName := chi.URLParam(r, "instance")
	inst := s.cfg.Instance(instName)
	if inst == nil {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	handle := r.FormValue("handle")
	email := r.FormValue("email")
	password := r.FormValue("password")
	if password == "" {
		password = randomPassword()
	}
	cli, err := goat.NewClient(s.cfg.Goat.BinaryPath, inst)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out, err := cli.AccountCreate(r.Context(), goat.CreateAccountInput{
		Handle: handle, Email: email, Password: password,
	})
	result := "ok"
	errMsg := ""
	if err != nil {
		result = "error"
		errMsg = err.Error()
	}
	s.audit.Log(audit.Entry{
		Subject: u.Subject, Email: u.Email, Provider: u.Provider,
		Instance: instName, Action: "account.create", Result: result, Error: errMsg,
		Args: map[string]string{"handle": handle, "email": email},
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	s.render(w, "account_created.html", map[string]any{
		"User":     u,
		"Instance": inst,
		"Handle":   handle,
		"Email":    email,
		"Password": password,
		"Output":   out,
	})
}

func (s *Server) accountTakedown(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if !auth.HasRole(u.Roles, "super-admin") && !auth.HasRole(u.Roles, "instance-admin") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	instName := chi.URLParam(r, "instance")
	inst := s.cfg.Instance(instName)
	if inst == nil {
		http.NotFound(w, r)
		return
	}
	user := chi.URLParam(r, "user")
	reverse := r.URL.Query().Get("reverse") == "1"
	cli, err := goat.NewClient(s.cfg.Goat.BinaryPath, inst)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = cli.AccountTakedown(r.Context(), user, reverse)
	action := "account.takedown"
	if reverse {
		action = "account.takedown.reverse"
	}
	result := "ok"
	errMsg := ""
	if err != nil {
		result = "error"
		errMsg = err.Error()
	}
	s.audit.Log(audit.Entry{
		Subject: u.Subject, Email: u.Email, Provider: u.Provider,
		Instance: instName, Action: action, Result: result, Error: errMsg,
		Args: map[string]string{"user": user},
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, "/instances/"+instName+"/accounts", http.StatusSeeOther)
}

func (s *Server) accountInfo(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	instName := chi.URLParam(r, "instance")
	inst := s.cfg.Instance(instName)
	if inst == nil {
		http.NotFound(w, r)
		return
	}
	user := chi.URLParam(r, "user")
	cli, err := goat.NewClient(s.cfg.Goat.BinaryPath, inst)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	info, err := cli.AccountInfo(r.Context(), user)
	result, errMsg := resultPair(err)
	s.audit.Log(audit.Entry{
		Subject: u.Subject, Email: u.Email, Provider: u.Provider,
		Instance: instName, Action: "account.info", Result: result, Error: errMsg,
		Args: map[string]string{"user": user},
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	pretty, _ := indentJSON(info)
	s.render(w, "account_info.html", map[string]any{
		"User":     u,
		"Instance": inst,
		"Account":  user,
		"Info":     pretty,
	})
}

func (s *Server) accountResetPassword(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if !auth.HasRole(u.Roles, "super-admin") && !auth.HasRole(u.Roles, "instance-admin") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	instName := chi.URLParam(r, "instance")
	inst := s.cfg.Instance(instName)
	if inst == nil {
		http.NotFound(w, r)
		return
	}
	user := chi.URLParam(r, "user")
	cli, err := goat.NewClient(s.cfg.Goat.BinaryPath, inst)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	pw, err := cli.AccountResetPassword(r.Context(), user)
	result, errMsg := resultPair(err)
	s.audit.Log(audit.Entry{
		Subject: u.Subject, Email: u.Email, Provider: u.Provider,
		Instance: instName, Action: "account.reset_password", Result: result, Error: errMsg,
		Args: map[string]string{"user": user},
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	s.render(w, "account_reset_password.html", map[string]any{
		"User":     u,
		"Instance": inst,
		"Account":  user,
		"Password": pw,
	})
}

func (s *Server) accountDelete(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if !auth.HasRole(u.Roles, "super-admin") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	instName := chi.URLParam(r, "instance")
	inst := s.cfg.Instance(instName)
	if inst == nil {
		http.NotFound(w, r)
		return
	}
	user := chi.URLParam(r, "user")
	if r.FormValue("confirm") != user {
		http.Error(w, "confirmation did not match account", http.StatusBadRequest)
		return
	}
	cli, err := goat.NewClient(s.cfg.Goat.BinaryPath, inst)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = cli.AccountDelete(r.Context(), user)
	result, errMsg := resultPair(err)
	s.audit.Log(audit.Entry{
		Subject: u.Subject, Email: u.Email, Provider: u.Provider,
		Instance: instName, Action: "account.delete", Result: result, Error: errMsg,
		Args: map[string]string{"user": user},
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, "/instances/"+instName+"/accounts", http.StatusSeeOther)
}

func (s *Server) accountUpdate(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if !auth.HasRole(u.Roles, "super-admin") && !auth.HasRole(u.Roles, "instance-admin") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	instName := chi.URLParam(r, "instance")
	inst := s.cfg.Instance(instName)
	if inst == nil {
		http.NotFound(w, r)
		return
	}
	user := chi.URLParam(r, "user")
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	in := goat.UpdateAccountInput{
		Email:  strings.TrimSpace(r.FormValue("email")),
		Handle: strings.TrimSpace(r.FormValue("handle")),
	}
	if in.Email == "" && in.Handle == "" {
		http.Error(w, "supply at least one of email/handle", http.StatusBadRequest)
		return
	}
	cli, err := goat.NewClient(s.cfg.Goat.BinaryPath, inst)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_, err = cli.AccountUpdate(r.Context(), user, in)
	result, errMsg := resultPair(err)
	args := map[string]string{"user": user}
	if in.Email != "" {
		args["email"] = in.Email
	}
	if in.Handle != "" {
		args["handle"] = in.Handle
	}
	s.audit.Log(audit.Entry{
		Subject: u.Subject, Email: u.Email, Provider: u.Provider,
		Instance: instName, Action: "account.update", Result: result, Error: errMsg, Args: args,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, "/instances/"+instName+"/accounts/"+user, http.StatusSeeOther)
}

func (s *Server) invitesForm(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	instName := chi.URLParam(r, "instance")
	inst := s.cfg.Instance(instName)
	if inst == nil {
		http.NotFound(w, r)
		return
	}
	s.render(w, "invites.html", map[string]any{"User": u, "Instance": inst})
}

func (s *Server) invitesCreate(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if !auth.HasRole(u.Roles, "super-admin") && !auth.HasRole(u.Roles, "instance-admin") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	instName := chi.URLParam(r, "instance")
	inst := s.cfg.Instance(instName)
	if inst == nil {
		http.NotFound(w, r)
		return
	}
	count := atoiOr(r.FormValue("count"), 1)
	uses := atoiOr(r.FormValue("uses"), 1)
	cli, err := goat.NewClient(s.cfg.Goat.BinaryPath, inst)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	codes, err := cli.CreateInvites(r.Context(), count, uses)
	result, errMsg := resultPair(err)
	s.audit.Log(audit.Entry{
		Subject: u.Subject, Email: u.Email, Provider: u.Provider,
		Instance: instName, Action: "invites.create", Result: result, Error: errMsg,
		Args: map[string]string{"count": fmt.Sprintf("%d", count), "uses": fmt.Sprintf("%d", uses)},
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	s.render(w, "invites_created.html", map[string]any{
		"User":     u,
		"Instance": inst,
		"Codes":    codes,
		"Uses":     uses,
	})
}

func (s *Server) blobForm(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	instName := chi.URLParam(r, "instance")
	inst := s.cfg.Instance(instName)
	if inst == nil {
		http.NotFound(w, r)
		return
	}
	s.render(w, "blob.html", map[string]any{"User": u, "Instance": inst})
}

func (s *Server) blobPurge(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if !auth.HasRole(u.Roles, "super-admin") && !auth.HasRole(u.Roles, "instance-admin") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	instName := chi.URLParam(r, "instance")
	inst := s.cfg.Instance(instName)
	if inst == nil {
		http.NotFound(w, r)
		return
	}
	user := strings.TrimSpace(r.FormValue("user"))
	cid := strings.TrimSpace(r.FormValue("cid"))
	reverse := r.FormValue("reverse") == "1"
	if user == "" || cid == "" {
		http.Error(w, "user and cid are required", http.StatusBadRequest)
		return
	}
	cli, err := goat.NewClient(s.cfg.Goat.BinaryPath, inst)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = cli.BlobPurge(r.Context(), user, cid, reverse)
	action := "blob.purge"
	if reverse {
		action = "blob.purge.reverse"
	}
	result, errMsg := resultPair(err)
	s.audit.Log(audit.Entry{
		Subject: u.Subject, Email: u.Email, Provider: u.Provider,
		Instance: instName, Action: action, Result: result, Error: errMsg,
		Args: map[string]string{"user": user, "cid": cid},
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	http.Redirect(w, r, "/instances/"+instName+"/blob", http.StatusSeeOther)
}

func (s *Server) crawlForm(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	instName := chi.URLParam(r, "instance")
	inst := s.cfg.Instance(instName)
	if inst == nil {
		http.NotFound(w, r)
		return
	}
	s.render(w, "crawl.html", map[string]any{"User": u, "Instance": inst})
}

func (s *Server) crawlRequest(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	if !auth.HasRole(u.Roles, "super-admin") && !auth.HasRole(u.Roles, "instance-admin") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	instName := chi.URLParam(r, "instance")
	inst := s.cfg.Instance(instName)
	if inst == nil {
		http.NotFound(w, r)
		return
	}
	relay := strings.TrimSpace(r.FormValue("relay"))
	if relay == "" {
		http.Error(w, "relay url required", http.StatusBadRequest)
		return
	}
	hostname := pdsHostFromURL(inst.PDSHost)
	err := goat.RequestCrawl(r.Context(), relay, hostname)
	result, errMsg := resultPair(err)
	s.audit.Log(audit.Entry{
		Subject: u.Subject, Email: u.Email, Provider: u.Provider,
		Instance: instName, Action: "relay.request_crawl", Result: result, Error: errMsg,
		Args: map[string]string{"relay": relay, "hostname": hostname},
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	s.render(w, "crawl_done.html", map[string]any{
		"User":     u,
		"Instance": inst,
		"Relay":    relay,
		"Hostname": hostname,
	})
}

func resultPair(err error) (string, string) {
	if err == nil {
		return "ok", ""
	}
	return "error", err.Error()
}

func indentJSON(b []byte) (string, error) {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return string(b), err
	}
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return string(b), err
	}
	return string(out), nil
}

func atoiOr(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		return def
	}
	return n
}

func pdsHostFromURL(u string) string {
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	if i := strings.IndexAny(u, "/?"); i != -1 {
		u = u[:i]
	}
	return u
}

func fullName(gu goth.User) string {
	if gu.Name != "" {
		return gu.Name
	}
	return strings.TrimSpace(gu.FirstName + " " + gu.LastName)
}

func randomPassword() string {
	b := make([]byte, 18)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
