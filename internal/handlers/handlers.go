package handlers

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/csv"
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
	"github.com/P3X-118/pds-pro/internal/linkage"
	"github.com/go-chi/chi/v5"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
)

type Templates map[string]*htmltemplate.Template

type Server struct {
	cfg       *config.Config
	tpl       Templates
	sessions  *auth.Manager
	audit     audit.Logger
	providers []string
	// link is the atproto cross-auth service; nil when federation is not
	// configured. The claim/broker routes and the provisioning webhook use it.
	link *linkage.Service
	// hookSecret authenticates the Authentik user-creation webhook; empty
	// disables the /hooks/authentik endpoint.
	hookSecret string
	// brokerSecret authenticates the internal atproto session-broker endpoint
	// (POST /internal/atproto-session), called server-to-server by chat (delta)
	// to embed Bluesky for an already-authenticated user; empty disables it.
	brokerSecret string
}

func New(cfg *config.Config, tpl Templates, sm *auth.Manager, al audit.Logger, providers []string, link *linkage.Service, hookSecret, brokerSecret string) *Server {
	return &Server{cfg: cfg, tpl: tpl, sessions: sm, audit: al, providers: providers, link: link, hookSecret: hookSecret, brokerSecret: brokerSecret}
}

func (s *Server) Routes() http.Handler {
	r := chi.NewRouter()

	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })

	r.Get("/login", s.login)
	r.Get("/auth/{provider}", s.authStart)
	r.Get("/auth/{provider}/callback", s.authCallback)
	r.Post("/logout", s.logout)

	// End-user atproto claim flow (cross-auth federation). Public entry; the
	// claim itself authenticates the end user via the cooey-brand "claim" OIDC
	// provider (NOT the operator allowlist). Paths avoid the /auth/{provider}
	// operator routes above. Mounted only when federation + claim are configured.
	if s.claimEnabled() {
		r.Get("/claim", s.claimForm)
		r.Get("/claim/auth", s.claimAuthStart)
		r.Get("/claim/callback", s.claimCallback)
	}

	// Authentik notification webhook: fired on user-creation (any source —
	// Discord login, chat SSO, the claim flow) to nudge a real-time provisioning
	// sweep. The body is ignored; it is a dumb authenticated "go check" kick, so
	// it is robust to Authentik's notification payload shape. The periodic sweep
	// is the backstop. Mounted only when a hook secret is configured.
	if s.link != nil && s.hookSecret != "" {
		r.Post("/hooks/authentik", s.authentikHook)
	}

	// Internal atproto session broker: chat (delta) authenticates the end user,
	// then calls this server-to-server (bearer broker secret, over the mesh /
	// same host) to obtain an atproto session for that user's OWN linked account,
	// so chat can embed Bluesky without a second login. NOT browser-facing.
	// Mounted only when federation + a broker secret are configured.
	if s.link != nil && s.brokerSecret != "" {
		r.Post("/internal/atproto-session", s.atprotoSession)
	}

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
		r.Get("/me", s.me)
		r.Get("/audit", s.auditList)
		r.Get("/audit.csv", s.auditCSV)
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
		Subject:   subject,
		Email:     gu.Email,
		Name:      fullName(gu),
		Provider:  provider,
		Roles:     decision.Roles,
		Instances: decision.Instances,
		IssuedAt:  time.Now().UTC(),
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
	visible := make([]config.PDSInstance, 0, len(s.cfg.Instances))
	for _, in := range s.cfg.Instances {
		if auth.CanAccessInstance(u.Roles, u.Instances, in.Name) {
			visible = append(visible, in)
		}
	}
	s.render(w, "home.html", map[string]any{
		"User":      u,
		"Instances": visible,
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
	if !auth.CanAccessInstance(u.Roles, u.Instances, instName) {
		http.Error(w, "forbidden", http.StatusForbidden)
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
	if !auth.CanAccessInstance(u.Roles, u.Instances, instName) {
		http.Error(w, "forbidden", http.StatusForbidden)
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
	if !auth.CanAccessInstance(u.Roles, u.Instances, instName) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	handle := strings.TrimSpace(r.FormValue("handle"))
	email := strings.TrimSpace(r.FormValue("email"))
	if email == "" {
		// Convention: derive the account email from the handle's domain, e.g.
		// handle "mike.eagledrive.live" -> email "mike@eagledrive.live". The
		// handle is the atproto identity (a hostname); the email is a separate
		// field, but by default it should live on the same domain as the user.
		email = deriveEmailFromHandle(handle)
	}
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
	if !auth.CanAccessInstance(u.Roles, u.Instances, instName) {
		http.Error(w, "forbidden", http.StatusForbidden)
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
	if !auth.CanAccessInstance(u.Roles, u.Instances, instName) {
		http.Error(w, "forbidden", http.StatusForbidden)
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
	if !auth.CanAccessInstance(u.Roles, u.Instances, instName) {
		http.Error(w, "forbidden", http.StatusForbidden)
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
	if !auth.CanAccessInstance(u.Roles, u.Instances, instName) {
		http.Error(w, "forbidden", http.StatusForbidden)
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
	if !auth.CanAccessInstance(u.Roles, u.Instances, instName) {
		http.Error(w, "forbidden", http.StatusForbidden)
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
	if !auth.CanAccessInstance(u.Roles, u.Instances, instName) {
		http.Error(w, "forbidden", http.StatusForbidden)
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
	if !auth.CanAccessInstance(u.Roles, u.Instances, instName) {
		http.Error(w, "forbidden", http.StatusForbidden)
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
	if !auth.CanAccessInstance(u.Roles, u.Instances, instName) {
		http.Error(w, "forbidden", http.StatusForbidden)
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
	if !auth.CanAccessInstance(u.Roles, u.Instances, instName) {
		http.Error(w, "forbidden", http.StatusForbidden)
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
	if !auth.CanAccessInstance(u.Roles, u.Instances, instName) {
		http.Error(w, "forbidden", http.StatusForbidden)
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
	if !auth.CanAccessInstance(u.Roles, u.Instances, instName) {
		http.Error(w, "forbidden", http.StatusForbidden)
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

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	s.render(w, "me.html", map[string]any{
		"User":      u,
		"Instances": s.cfg.Instances,
		"Providers": s.providers,
	})
}

func (s *Server) auditList(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	q, ok := s.audit.(audit.Querier)
	if !ok {
		s.render(w, "audit_unavailable.html", map[string]any{"User": u})
		return
	}
	filter := parseAuditFilter(r)
	entries, err := q.ListEntries(r.Context(), filter)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.render(w, "audit.html", map[string]any{
		"User":        u,
		"Entries":     entries,
		"Filter":      filter,
		"Instances":   s.cfg.Instances,
		"QueryString": r.URL.RawQuery,
	})
}

func (s *Server) auditCSV(w http.ResponseWriter, r *http.Request) {
	u := auth.UserFromContext(r.Context())
	q, ok := s.audit.(audit.Querier)
	if !ok {
		http.Error(w, "audit query backend not enabled (set audit.db_path in config)", http.StatusNotImplemented)
		return
	}
	filter := parseAuditFilter(r)
	if filter.Limit <= 0 {
		filter.Limit = 100000
	}
	entries, err := q.ListEntries(r.Context(), filter)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.audit.Log(audit.Entry{
		Subject: u.Subject, Email: u.Email, Provider: u.Provider,
		Action: "audit.export", Result: "ok",
		Args: map[string]string{"rows": strconv.Itoa(len(entries))},
	})

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="audit.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"ts", "subject", "email", "provider", "instance", "action", "args", "result", "http_status", "error"})
	for _, e := range entries {
		argsJSON := ""
		if len(e.Args) > 0 {
			b, _ := json.Marshal(e.Args)
			argsJSON = string(b)
		}
		httpStatus := ""
		if e.HTTPStatus != 0 {
			httpStatus = strconv.Itoa(e.HTTPStatus)
		}
		_ = cw.Write([]string{
			e.TS.UTC().Format(time.RFC3339),
			e.Subject, e.Email, e.Provider, e.Instance, e.Action,
			argsJSON, e.Result, httpStatus, e.Error,
		})
	}
	cw.Flush()
}

func parseAuditFilter(r *http.Request) audit.Filter {
	q := r.URL.Query()
	f := audit.Filter{
		Subject:  q.Get("subject"),
		Action:   q.Get("action"),
		Instance: q.Get("instance"),
		Result:   q.Get("result"),
		Limit:    atoiOr(q.Get("limit"), 200),
	}
	if s := q.Get("since"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			f.Since = t
		} else if t, err := time.Parse("2006-01-02", s); err == nil {
			f.Since = t
		}
	}
	if s := q.Get("until"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			f.Until = t
		} else if t, err := time.Parse("2006-01-02", s); err == nil {
			f.Until = t.Add(24 * time.Hour)
		}
	}
	return f
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

// deriveEmailFromHandle turns an atproto handle into the convention account
// email by replacing the first dot with "@": "mike.eagledrive.live" ->
// "mike@eagledrive.live". Returns "" if the handle has no usable domain part
// (caller then falls back to whatever was submitted, and goat validates).
func deriveEmailFromHandle(handle string) string {
	h := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(handle), "@"))
	i := strings.IndexByte(h, '.')
	if i <= 0 || i >= len(h)-1 {
		return ""
	}
	return h[:i] + "@" + h[i+1:]
}

// ---- end-user atproto claim flow (cross-auth federation) -------------------

func (s *Server) claimEnabled() bool {
	return s.link != nil && s.cfg.Atproto != nil && s.cfg.Atproto.Claim != nil
}

// claimForm shows the public "pick a handle" page.
func (s *Server) claimForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, "claim.html", map[string]any{"HandleDomain": s.cfg.Atproto.HandleDomain})
}

func (s *Server) claimAuthStart(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	q.Set("provider", "claim")
	r.URL.RawQuery = q.Encode()
	gothic.BeginAuthHandler(w, r)
}

// claimCallback completes the OIDC round-trip and provisions+links the account.
// The handle localpart IS the user's chat/Authentik username — chat shows
// <user>, bsky shows <user>.cooey.club (one identity), so there is no separate
// handle pick. Provisioning is non-blocking: even on failure the user was
// already flagged + alerted, so we render the outcome rather than erroring out.
func (s *Server) claimCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	q.Set("provider", "claim")
	r.URL.RawQuery = q.Encode()

	gu, err := gothic.CompleteUserAuth(w, r)
	if err != nil {
		http.Error(w, "auth failed: "+err.Error(), http.StatusUnauthorized)
		return
	}
	username, _ := gu.RawData["preferred_username"].(string)
	if username == "" {
		username = gu.NickName
	}
	res, perr := s.link.ProvisionAndLink(r.Context(), linkage.ClaimInput{
		Sub:       gu.UserID,
		Username:  username,
		Email:     gu.Email,
		Localpart: username,
	})
	appPassword := ""
	if perr == nil && res.Status == "active" {
		// Best-effort: hand the user an app-password for external Bluesky apps.
		// A failure here does not undo the (successful) claim.
		appPassword, _ = s.link.IssueAppPassword(r.Context(), res.Handle, "cooey")
	}
	s.render(w, "claim_done.html", map[string]any{
		"Handle":      res.Handle,
		"DID":         res.DID,
		"Status":      res.Status,
		"Error":       errString(perr),
		"AppPassword": appPassword,
	})
}

func errString(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}

// authentikHook is the Authentik user-creation webhook. It authenticates the
// caller and kicks an idempotent provisioning sweep, then returns immediately —
// the sweep runs in the background loop. The request body is intentionally
// ignored (see the route comment).
func (s *Server) authentikHook(w http.ResponseWriter, r *http.Request) {
	if !s.hookAuthorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	s.link.Kick()
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte("queued"))
}

// hookAuthorized accepts the shared secret either as a bearer token or a ?token=
// query param (Authentik's webhook transport can carry it whichever way the
// deployed version supports). Constant-time compared.
func (s *Server) hookAuthorized(r *http.Request) bool {
	want := []byte(s.hookSecret)
	if want == nil || len(want) == 0 {
		return false
	}
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		if subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(h, "Bearer ")), want) == 1 {
			return true
		}
	}
	if t := r.URL.Query().Get("token"); t != "" {
		if subtle.ConstantTimeCompare([]byte(t), want) == 1 {
			return true
		}
	}
	return false
}

// atprotoSession brokers an atproto session for an already-authenticated cooey
// user so a first-party surface (chat) can embed Bluesky without a separate
// login. INTERNAL ONLY: authenticated by the broker shared secret and called
// server-to-server by delta (which authenticates the end user and passes their
// email); never exposed to browsers. The handle is resolved from Authentik (not
// taken from input), so a caller only ever obtains the named user's OWN session.
func (s *Server) atprotoSession(w http.ResponseWriter, r *http.Request) {
	if !s.brokerAuthorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var body struct {
		Email    string `json:"email"`
		Username string `json:"username"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	email := strings.TrimSpace(body.Email)
	username := strings.TrimSpace(body.Username)
	if email == "" && username == "" {
		http.Error(w, "email or username required", http.StatusBadRequest)
		return
	}
	sess, err := s.link.BrokerSessionForUser(r.Context(), email, username)
	if err != nil {
		http.Error(w, "no linked atproto account", http.StatusNotFound)
		return
	}
	pds := ""
	if s.cfg.Atproto != nil {
		if inst := s.cfg.Instance(s.cfg.Atproto.Instance); inst != nil {
			pds = inst.PDSHost
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"accessJwt":  sess.AccessJwt,
		"refreshJwt": sess.RefreshJwt,
		"did":        sess.DID,
		"handle":     sess.Handle,
		"pds":        pds,
	})
}

// brokerAuthorized constant-time compares the request bearer token against the
// broker secret. Bearer only (server-to-server; no query-param fallback).
func (s *Server) brokerAuthorized(r *http.Request) bool {
	want := []byte(s.brokerSecret)
	if len(want) == 0 {
		return false
	}
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(h, "Bearer ")), want) == 1
}
