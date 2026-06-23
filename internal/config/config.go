package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ListenAddr string        `yaml:"listen_addr"`
	BaseURL    string        `yaml:"base_url"`
	Session    SessionConfig `yaml:"session"`
	OAuth      OAuthConfig   `yaml:"oauth"`
	Allowlist  []AllowEntry  `yaml:"allowlist"`
	Instances  []PDSInstance `yaml:"instances"`
	Audit      AuditConfig   `yaml:"audit"`
	Goat       GoatConfig    `yaml:"goat"`

	// Cross-auth federation (the "session-broker" identity model). When all
	// three blocks are present, pds-pro can provision a <handle>.<handle_domain>
	// atproto account for an Authentik-authed user and link the DID/handle back
	// onto the Authentik user. See pds-pro memory crossauth-atproto-federation.md.
	Authentik *AuthentikConfig `yaml:"authentik,omitempty"`
	Ntfy      *NtfyConfig      `yaml:"ntfy,omitempty"`
	Atproto   *AtprotoConfig   `yaml:"atproto,omitempty"`
}

type SessionConfig struct {
	SecretFile string `yaml:"secret_file"`
	Secure     bool   `yaml:"secure"`
	MaxAgeSec  int    `yaml:"max_age_sec"`
}

type OAuthConfig struct {
	OIDC      *OIDCProvider    `yaml:"oidc,omitempty"`
	Okta      *OktaProvider    `yaml:"okta,omitempty"`
	Google    *GenericProvider `yaml:"google,omitempty"`
	Microsoft *GenericProvider `yaml:"microsoft,omitempty"`
	Facebook  *GenericProvider `yaml:"facebook,omitempty"`
	Twitter   *GenericProvider `yaml:"twitter,omitempty"`
}

// OIDCProvider is a generic OpenID Connect provider. Unlike the vendor
// providers above, endpoints are resolved at startup via OIDC discovery
// (issuer_url + "/.well-known/openid-configuration"), so any compliant IdP
// (e.g. self-hosted Authentik) works without vendor-specific URL schemes.
type OIDCProvider struct {
	IssuerURL        string   `yaml:"issuer_url"`
	ClientID         string   `yaml:"client_id"`
	ClientSecretFile string   `yaml:"client_secret_file"`
	CallbackURL      string   `yaml:"callback_url"`
	Scopes           []string `yaml:"scopes,omitempty"`
}

type OktaProvider struct {
	OrgURL           string `yaml:"org_url"`
	ClientID         string `yaml:"client_id"`
	ClientSecretFile string `yaml:"client_secret_file"`
	CallbackURL      string `yaml:"callback_url"`
}

type GenericProvider struct {
	ClientID         string   `yaml:"client_id"`
	ClientSecretFile string   `yaml:"client_secret_file"`
	CallbackURL      string   `yaml:"callback_url"`
	Scopes           []string `yaml:"scopes,omitempty"`
}

type AllowEntry struct {
	Subject     string   `yaml:"subject,omitempty"`
	Email       string   `yaml:"email,omitempty"`
	EmailDomain string   `yaml:"email_domain,omitempty"`
	Roles       []string `yaml:"roles"`
	// Instances this identity may manage. Ignored for the "super-admin"
	// role (which sees every instance). For non-super entries an empty
	// list means the identity can manage NO instances (deny by default).
	Instances []string `yaml:"instances,omitempty"`
}

type PDSInstance struct {
	Name              string `yaml:"name"`
	PDSHost           string `yaml:"pds_host"`
	AdminPasswordFile string `yaml:"admin_password_file"`
}

type AuditConfig struct {
	// Preferred: SQLite database. Enables the /audit and /audit.csv views.
	DBPath string `yaml:"db_path"`
	// Fallback: append-only JSON-lines file. If both paths are empty, audit
	// entries go to stdout. If db_path is set, log_path is ignored.
	LogPath string `yaml:"log_path"`
}

type GoatConfig struct {
	BinaryPath string `yaml:"binary_path"`
}

// AuthentikConfig is the Authentik API pds-pro uses to write a user's linked
// atproto identity back onto their Authentik account
// (attributes.atproto.{did,handle,status}). Token = the svc-pds-pro-atproto-writer
// API token (view_user + change_user), provisioned by
// apps/authentik/scripts/sgc/provision-atproto-writer-token.py.
type AuthentikConfig struct {
	BaseURL   string `yaml:"base_url"`   // e.g. https://auth.cooey.club (reachable over the SGC mesh)
	TokenFile string `yaml:"token_file"` // single-line Authentik API token
}

// NtfyConfig is the ntfy topic pds-pro posts to when an atproto provisioning
// attempt fails. Provisioning is non-blocking: the user is flagged
// status="error" and this alert lets an operator (or the reconciler) follow up.
type NtfyConfig struct {
	BaseURL   string `yaml:"base_url"`             // e.g. https://ntfy.<host>
	Topic     string `yaml:"topic"`                // e.g. eagledrive-admin
	TokenFile string `yaml:"token_file,omitempty"` // optional bearer token for protected topics
}

// AtprotoConfig binds the cross-auth federation to one PDS instance + handle
// domain, and to the secret pds-pro derives per-account managed passwords from
// (so it can later broker atproto sessions on a user's behalf without storing
// per-user plaintext). The managed password is derived from the Authentik OIDC
// `sub` (stable per user, known at claim time, survives handle changes).
type AtprotoConfig struct {
	Instance                  string `yaml:"instance"`                     // name of the PDSInstance that hosts claimed accounts (e.g. "cooey")
	HandleDomain              string `yaml:"handle_domain"`                // e.g. cooey.club -> handles <localpart>.cooey.club
	ManagedPasswordSecretFile string `yaml:"managed_password_secret_file"` // secret (sgc_pgsk / resolver) used to derive per-account passwords

	// Claim is the END-USER OIDC client for the self-service "/claim" flow
	// (distinct from the operator login: it points at the cooey brand and is
	// NOT allowlist-gated, so any cooey user can claim a handle). Optional; the
	// /claim routes only mount when it is configured.
	Claim *ClaimOIDC `yaml:"claim,omitempty"`

	// WebhookSecretFile authenticates the inbound Authentik notification webhook
	// that nudges a real-time provisioning sweep (POST /hooks/authentik). The
	// same secret is configured on the Authentik notification transport. Optional
	// — if empty, the endpoint is disabled and only the periodic sweep runs.
	WebhookSecretFile string `yaml:"webhook_secret_file,omitempty"`

	// MemberGroup scopes auto-provisioning to ONE Authentik group (the cooey
	// members). REQUIRED on a shared Authentik: cooey shares its Authentik with
	// other brands (eagledrive, bskypds.pro, …), so without this the sweep would
	// mint <user>.cooey.club handles for every user including other brands'
	// operators. Cooey users join this group by authorizing a cooey application
	// (chat=stoked, bsky=pds-pro-claim). Empty => the sweep provisions NOBODY (a
	// safe no-op), so the endpoint/loop can ship before the group is populated.
	MemberGroup string `yaml:"member_group,omitempty"`
}

// ClaimOIDC is the end-user OpenID Connect client used by the /claim flow. Same
// shape as OIDCProvider but registered as a separate goth provider ("claim")
// that never appears as an operator login button. Point issuer_url at the cooey
// brand (https://auth.cooey.club/application/o/<client>/) so users see the cooey
// login + Discord source; callback_url must be <base_url>/claim/callback.
type ClaimOIDC struct {
	IssuerURL        string   `yaml:"issuer_url"`
	ClientID         string   `yaml:"client_id"`
	ClientSecretFile string   `yaml:"client_secret_file"`
	CallbackURL      string   `yaml:"callback_url"`
	Scopes           []string `yaml:"scopes,omitempty"`
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if c.ListenAddr == "" {
		c.ListenAddr = ":8080"
	}
	if c.Session.MaxAgeSec == 0 {
		c.Session.MaxAgeSec = 86400
	}
	if c.Goat.BinaryPath == "" {
		c.Goat.BinaryPath = "goat"
	}
	if c.OAuth.OIDC == nil && c.OAuth.Okta == nil && c.OAuth.Google == nil && c.OAuth.Microsoft == nil && c.OAuth.Facebook == nil && c.OAuth.Twitter == nil {
		return nil, fmt.Errorf("at least one OAuth provider must be configured")
	}
	if len(c.Instances) == 0 {
		return nil, fmt.Errorf("at least one PDS instance must be configured")
	}
	// Cross-auth federation is optional, but if the atproto block is present the
	// authentik block and the named instance must be too.
	if c.Atproto != nil {
		if c.Authentik == nil || c.Authentik.BaseURL == "" || c.Authentik.TokenFile == "" {
			return nil, fmt.Errorf("atproto config requires an authentik block with base_url + token_file")
		}
		if c.Atproto.Instance == "" || c.Atproto.HandleDomain == "" || c.Atproto.ManagedPasswordSecretFile == "" {
			return nil, fmt.Errorf("atproto config requires instance, handle_domain, and managed_password_secret_file")
		}
		if c.Instance(c.Atproto.Instance) == nil {
			return nil, fmt.Errorf("atproto.instance %q is not a configured PDS instance", c.Atproto.Instance)
		}
		// The end-user claim flow is optional, but if present it must be complete.
		if cl := c.Atproto.Claim; cl != nil {
			if cl.IssuerURL == "" || cl.ClientID == "" || cl.ClientSecretFile == "" || cl.CallbackURL == "" {
				return nil, fmt.Errorf("atproto.claim requires issuer_url, client_id, client_secret_file, callback_url")
			}
		}
	}
	return &c, nil
}

func (c *Config) Instance(name string) *PDSInstance {
	for i := range c.Instances {
		if c.Instances[i].Name == name {
			return &c.Instances[i]
		}
	}
	return nil
}

func ReadSecretFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read secret %s: %w", path, err)
	}
	return string(trimNewline(b)), nil
}

func trimNewline(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}
