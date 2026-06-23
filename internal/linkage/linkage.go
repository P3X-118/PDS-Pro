// Package linkage is the pds-pro management-plane flow that provisions a
// <handle>.<handle_domain> atproto account on the configured PDS for an
// Authentik user and links the resulting DID/handle back onto the Authentik
// user. It is the heart of the Discord->Authentik->Stoked+bsky cross-auth
// ("session-broker") model. See pds-pro memory crossauth-atproto-federation.md.
//
// Source-agnostic provisioning: an account is created whenever an Authentik
// *user* appears, no matter the door (Discord login, the bsky /claim flow, or a
// chat.cooey.club SSO signup). Two triggers feed the same idempotent path:
//   - Kick()  — a real-time nudge from the Authentik user-creation webhook.
//   - Run()   — a periodic sweep (backstop) that ensures every Authentik user
//     has an active account, and retries any flagged with status="error".
//
// Failure is NON-BLOCKING: if account creation or link-back fails, the user is
// flagged attributes.atproto.status="error", an ntfy alert fires (once, not on
// every quiet retry), and the error is returned for the caller to surface gently
// — onboarding is never blocked over it.
//
// The session broker (IssueAppPassword / BrokerSession) leans on the same
// managed password: pds-pro set it at creation and re-derives it from the stable
// handle localpart (== the Authentik username), so it can mint sessions /
// app-passwords for a user without storing per-user plaintext.
package linkage

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/P3X-118/pds-pro/internal/atproto"
	"github.com/P3X-118/pds-pro/internal/audit"
	"github.com/P3X-118/pds-pro/internal/authentik"
	"github.com/P3X-118/pds-pro/internal/config"
	"github.com/P3X-118/pds-pro/internal/goat"
	"github.com/P3X-118/pds-pro/internal/ntfy"
)

type Service struct {
	cfg           *config.Config
	ak            *authentik.Client
	ntfy          *ntfy.Client
	audit         audit.Logger
	managedSecret string

	// trigger coalesces real-time sweep nudges from the webhook (buffered 1).
	trigger chan struct{}

	// per-localpart locks serialize concurrent provisioning of the same user
	// (webhook + periodic sweep can race), so create+link is check-then-act safe.
	locksMu sync.Mutex
	locks   map[string]*sync.Mutex
}

func NewService(cfg *config.Config, ak *authentik.Client, n *ntfy.Client, al audit.Logger, managedSecret string) *Service {
	return &Service{
		cfg: cfg, ak: ak, ntfy: n, audit: al, managedSecret: managedSecret,
		trigger: make(chan struct{}, 1),
		locks:   map[string]*sync.Mutex{},
	}
}

// ClaimInput identifies the Authentik user to provision. Username resolves the
// account to PATCH and is the handle localpart; Sub is stored on the linkage
// record for reference only (the managed password is keyed on the localpart, not
// the sub, so every entry point derives the same password).
type ClaimInput struct {
	Sub       string
	Username  string
	Email     string
	Localpart string
}

type Result struct {
	Handle string
	DID    string
	Status string // "active" | "error"
}

// ReconcileSummary tallies one sweep over all Authentik users.
type ReconcileSummary struct {
	Active    int // already provisioned, skipped
	New       int // first-time provision attempted
	Retried   int // previously errored, re-attempted
	Recovered int // provisioned or relinked successfully this pass
	Failed    int // attempt failed (flagged, will retry next pass)
	Skipped   int // not provisionable (service account / empty username)
}

// ManagedPassword derives the deterministic atproto account password from the
// (sanitized) handle localpart — which equals the user's Authentik username, the
// one key shared by every entry point (the claim OIDC `preferred_username` claim
// and the Authentik API `username`). pds-pro sets this at account creation and
// re-derives it to broker sessions / app-passwords without storing per-user
// plaintext. This derivation is pds-pro-internal (NOT the sgc_pgsk derivation).
func (s *Service) ManagedPassword(localpart string) string {
	mac := hmac.New(sha256.New, []byte(s.managedSecret))
	mac.Write([]byte("atproto:account:" + sanitizeLocalpart(localpart)))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))[:24]
}

// IssueAppPassword mints a revocable app-password for the user's account, for
// use in external Bluesky clients. handle is the account handle (the managed
// password is re-derived from its localpart).
func (s *Service) IssueAppPassword(ctx context.Context, handle, name string) (string, error) {
	inst, err := s.atprotoInstance()
	if err != nil {
		return "", err
	}
	sess, err := atproto.CreateSession(ctx, inst.PDSHost, handle, s.ManagedPassword(localpartOf(handle)))
	if err != nil {
		return "", fmt.Errorf("broker: create session: %w", err)
	}
	pw, err := atproto.CreateAppPassword(ctx, inst.PDSHost, sess.AccessJwt, name)
	if err != nil {
		return "", fmt.Errorf("broker: create app password: %w", err)
	}
	return pw, nil
}

// BrokerSession mints a full atproto session on the user's behalf (used by
// first-party surfaces like chat to embed bsky without a separate login).
func (s *Service) BrokerSession(ctx context.Context, handle string) (*atproto.Session, error) {
	inst, err := s.atprotoInstance()
	if err != nil {
		return nil, err
	}
	return atproto.CreateSession(ctx, inst.PDSHost, handle, s.ManagedPassword(localpartOf(handle)))
}

func (s *Service) atprotoInstance() (*config.PDSInstance, error) {
	if s.cfg.Atproto == nil {
		return nil, fmt.Errorf("linkage: atproto federation not configured")
	}
	inst := s.cfg.Instance(s.cfg.Atproto.Instance)
	if inst == nil {
		return nil, fmt.Errorf("linkage: instance %q not configured", s.cfg.Atproto.Instance)
	}
	return inst, nil
}

// ProvisionAndLink is the public entrypoint for an explicit claim (the /claim
// callback). It is idempotent: if the user already has an active account it is a
// no-op. On failure the user is flagged AND an ntfy alert fires; treat
// provisioning as best-effort (do not block the user on a non-nil error).
func (s *Service) ProvisionAndLink(ctx context.Context, in ClaimInput) (Result, error) {
	return s.provisionAndLink(ctx, in, false)
}

func (s *Service) provisionAndLink(ctx context.Context, in ClaimInput, quiet bool) (Result, error) {
	ac := s.cfg.Atproto
	if ac == nil {
		return Result{}, fmt.Errorf("linkage: atproto federation not configured")
	}
	localpart := sanitizeLocalpart(in.Localpart)
	if localpart == "" {
		return Result{}, fmt.Errorf("linkage: empty/invalid handle localpart")
	}
	handle := localpart + "." + ac.HandleDomain
	email := in.Email
	if email == "" {
		email = localpart + "@" + ac.HandleDomain
	}

	// Serialize concurrent provisioning of the same user (webhook vs sweep).
	lk := s.userLock(localpart)
	lk.Lock()
	defer lk.Unlock()

	// Resolve the Authentik user up-front so we can flag it on any later failure.
	user, err := s.ak.FindUser(ctx, authentik.Lookup{Username: in.Username, Email: in.Email})
	if err != nil {
		return Result{}, fmt.Errorf("linkage: resolve authentik user: %w", err)
	}

	// Idempotent: already provisioned (covers webhook+sweep races and repeat
	// claims) — never re-create.
	if ap := user.Atproto(); ap != nil && ap.Status == "active" && ap.DID != "" {
		return Result{Handle: ap.Handle, DID: ap.DID, Status: "active"}, nil
	}

	inst := s.cfg.Instance(ac.Instance)
	if inst == nil {
		return Result{}, fmt.Errorf("linkage: instance %q not configured", ac.Instance)
	}
	cli, err := goat.NewClient(s.cfg.Goat.BinaryPath, inst)
	if err != nil {
		s.fail(ctx, in, user, handle, "", "goat client: "+err.Error(), quiet)
		return Result{Handle: handle, Status: "error"}, err
	}

	out, err := cli.AccountCreate(ctx, goat.CreateAccountInput{
		Handle:   handle,
		Email:    email,
		Password: s.ManagedPassword(localpart),
	})
	if err != nil {
		// Idempotency across the PDS (not just the Authentik record): if the
		// handle already exists (a prior create whose link-back never landed, or
		// a manual account), recover by resolving the DID and linking it back
		// rather than flagging error forever.
		if isHandleTaken(err) {
			if did, rerr := atproto.ResolveHandle(ctx, inst.PDSHost, handle); rerr == nil && did != "" {
				if lerr := s.link(ctx, user, in.Sub, did, handle, inst.PDSHost); lerr != nil {
					s.fail(ctx, in, user, handle, did, "link-back (recover existing): "+lerr.Error(), quiet)
					return Result{Handle: handle, DID: did, Status: "error"}, lerr
				}
				s.audit.Log(audit.Entry{
					TS: time.Now().UTC(), Subject: in.Sub, Email: in.Email, Provider: "oidc",
					Instance: ac.Instance, Action: "atproto.provision", Result: "ok",
					Args: map[string]string{"handle": handle, "did": did, "mode": "recovered-existing"},
				})
				return Result{Handle: handle, DID: did, Status: "active"}, nil
			}
		}
		s.fail(ctx, in, user, handle, "", "account create: "+err.Error(), quiet)
		return Result{Handle: handle, Status: "error"}, err
	}
	did := extractDID(out)

	if err := s.link(ctx, user, in.Sub, did, handle, inst.PDSHost); err != nil {
		// The account exists but link-back failed; flag (with the did) so the
		// reconciler can relink without re-creating.
		s.fail(ctx, in, user, handle, did, "link-back: "+err.Error(), quiet)
		return Result{Handle: handle, DID: did, Status: "error"}, err
	}

	s.audit.Log(audit.Entry{
		TS: time.Now().UTC(), Subject: in.Sub, Email: in.Email, Provider: "oidc",
		Instance: ac.Instance, Action: "atproto.provision", Result: "ok",
		Args: map[string]string{"handle": handle, "did": did},
	})
	return Result{Handle: handle, DID: did, Status: "active"}, nil
}

func (s *Service) link(ctx context.Context, user *authentik.User, sub, did, handle, pds string) error {
	return s.ak.SetAtproto(ctx, user, authentik.Atproto{Sub: sub, DID: did, Handle: handle, Status: "active", PDS: pds})
}

// Reconcile sweeps every provisionable member of the configured cooey group
// (Atproto.MemberGroup) and ensures each has an active atproto account: it
// provisions members with no account yet (chat / Discord / claim signups not
// wired inline) and retries any flagged status="error" (relinking when a DID
// already exists, else re-creating). Group scoping is what makes this both
// source-agnostic AND safe on the shared Authentik — the trigger is cooey
// membership, not which page the user arrived through. Retries are quiet (no
// ntfy) so a stuck account does not re-alert every cycle.
func (s *Service) Reconcile(ctx context.Context) (ReconcileSummary, error) {
	var sum ReconcileSummary
	if s.cfg.Atproto == nil {
		return sum, nil
	}
	// Shared-Authentik safety: only ever sweep the configured cooey-members
	// group. With no group set we provision nobody (rather than every brand's
	// users) — see config.AtprotoConfig.MemberGroup.
	mg := strings.TrimSpace(s.cfg.Atproto.MemberGroup)
	if mg == "" {
		return sum, nil
	}
	users, err := s.ak.ListUsers(ctx, mg)
	if err != nil {
		return sum, fmt.Errorf("reconcile: list group %q users: %w", mg, err)
	}
	for i := range users {
		u := &users[i]
		if !u.Provisionable() {
			sum.Skipped++
			continue
		}
		ap := u.Atproto()
		if ap != nil && ap.Status == "active" && ap.DID != "" {
			sum.Active++
			continue
		}
		if sanitizeLocalpart(u.Username) == "" {
			sum.Skipped++
			continue
		}
		retry := ap != nil && ap.Status == "error"

		// Relink fast-path: the account exists, only the link-back failed before.
		if retry && ap.DID != "" {
			if err := s.link(ctx, u, ap.Sub, ap.DID, ap.Handle, ap.PDS); err != nil {
				sum.Failed++
				continue
			}
			sum.Recovered++
			s.audit.Log(audit.Entry{
				TS: time.Now().UTC(), Subject: ap.Sub, Provider: "oidc",
				Instance: s.cfg.Atproto.Instance, Action: "atproto.reconcile", Result: "ok",
				Args: map[string]string{"handle": ap.Handle, "did": ap.DID, "mode": "relink"},
			})
			continue
		}

		if retry {
			sum.Retried++
		} else {
			sum.New++
		}
		in := ClaimInput{Sub: subOf(u, ap), Username: u.Username, Email: u.Email, Localpart: u.Username}
		res, err := s.provisionAndLink(ctx, in, retry)
		if err != nil || res.Status != "active" {
			sum.Failed++
			continue
		}
		sum.Recovered++
	}
	return sum, nil
}

// Run is the provisioning loop: it sweeps on a periodic tick (backstop) and on
// every Kick() (real-time webhook nudge). Both call the same idempotent
// Reconcile. Blocks until ctx is cancelled.
func (s *Service) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 2 * time.Minute
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.trigger:
		}
		c, cancel := context.WithTimeout(ctx, 2*time.Minute)
		sum, err := s.Reconcile(c)
		cancel()
		switch {
		case err != nil:
			log.Printf("atproto sweep: %v", err)
		case sum.New+sum.Retried+sum.Recovered+sum.Failed > 0:
			log.Printf("atproto sweep: new=%d retried=%d recovered=%d failed=%d active=%d skipped=%d",
				sum.New, sum.Retried, sum.Recovered, sum.Failed, sum.Active, sum.Skipped)
		}
	}
}

// Kick requests a sweep as soon as the loop is free (coalesced — extra kicks
// during an in-flight sweep collapse into one follow-up pass). Safe from any
// goroutine; never blocks.
func (s *Service) Kick() {
	select {
	case s.trigger <- struct{}{}:
	default:
	}
}

func (s *Service) userLock(key string) *sync.Mutex {
	s.locksMu.Lock()
	defer s.locksMu.Unlock()
	m := s.locks[key]
	if m == nil {
		m = &sync.Mutex{}
		s.locks[key] = m
	}
	return m
}

// fail flags the Authentik user (status=error, carrying sub + any known did),
// optionally alerts ntfy, and audits — all best-effort so the caller's flow is
// never blocked.
func (s *Service) fail(ctx context.Context, in ClaimInput, user *authentik.User, handle, did, reason string, quiet bool) {
	if user != nil {
		_ = s.ak.SetAtproto(ctx, user, authentik.Atproto{
			Sub: in.Sub, DID: did, Handle: handle, Status: "error", Error: reason,
		})
	}
	if !quiet {
		_ = s.ntfy.Publish(ctx,
			"atproto provision failed",
			fmt.Sprintf("handle=%s user=%s: %s", handle, userLabel(in, user), reason),
			4, "warning,rotating_light",
		)
	}
	inst := ""
	if s.cfg.Atproto != nil {
		inst = s.cfg.Atproto.Instance
	}
	s.audit.Log(audit.Entry{
		TS: time.Now().UTC(), Subject: in.Sub, Email: in.Email, Provider: "oidc",
		Instance: inst, Action: "atproto.provision", Result: "error",
		Args: map[string]string{"handle": handle}, Error: reason,
	})
}

func userLabel(in ClaimInput, u *authentik.User) string {
	if u != nil && u.Username != "" {
		return u.Username
	}
	if in.Username != "" {
		return in.Username
	}
	return in.Email
}

// subOf returns the linkage sub to record: the prior record's sub if present,
// else the Authentik user pk (informational only — not used for the password).
func subOf(u *authentik.User, ap *authentik.Atproto) string {
	if ap != nil && ap.Sub != "" {
		return ap.Sub
	}
	return strconv.Itoa(u.PK)
}

// sanitizeLocalpart keeps an atproto-handle-safe localpart (lowercase a-z0-9-,
// no leading/trailing hyphen).
func sanitizeLocalpart(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		}
	}
	return strings.Trim(b.String(), "-")
}

// localpartOf returns the first label of a handle (alice.cooey.club -> alice).
func localpartOf(handle string) string {
	if i := strings.IndexByte(handle, '.'); i > 0 {
		return handle[:i]
	}
	return handle
}

// isHandleTaken reports whether a goat account-create error is the PDS rejecting
// a handle that already exists (so we recover/relink instead of failing).
func isHandleTaken(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "already taken") ||
		strings.Contains(s, "already exists") ||
		strings.Contains(s, "handle already") ||
		strings.Contains(s, "already registered")
}

// extractDID pulls the did:... token out of goat's account-create output.
func extractDID(out string) string {
	for _, f := range strings.Fields(out) {
		if strings.HasPrefix(f, "did:") {
			return strings.TrimRight(f, ",")
		}
	}
	return strings.TrimSpace(out)
}
