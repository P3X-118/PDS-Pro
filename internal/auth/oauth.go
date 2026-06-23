package auth

import (
	"fmt"
	"strings"

	"github.com/P3X-118/pds-pro/internal/config"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/facebook"
	"github.com/markbates/goth/providers/google"
	"github.com/markbates/goth/providers/microsoftonline"
	"github.com/markbates/goth/providers/okta"
	"github.com/markbates/goth/providers/openidConnect"
	"github.com/markbates/goth/providers/twitterv2"
)

// RegisterProviders configures every OAuth provider that has a config block,
// and points gothic at the same cookie store our app uses so OAuth state is
// signed with the same secret as user sessions.
func RegisterProviders(cfg *config.Config, sm *Manager) ([]string, error) {
	gothic.Store = sm.store

	var enabled []string
	var providers []goth.Provider

	if o := cfg.OAuth.OIDC; o != nil {
		if o.ClientID == "" || o.IssuerURL == "" || o.CallbackURL == "" {
			return nil, fmt.Errorf("oidc provider requires client_id, issuer_url, callback_url")
		}
		secret, err := config.ReadSecretFile(o.ClientSecretFile)
		if err != nil {
			return nil, fmt.Errorf("oidc secret: %w", err)
		}
		scopes := o.Scopes
		if len(scopes) == 0 {
			scopes = []string{"openid", "profile", "email"}
		}
		discovery := strings.TrimRight(o.IssuerURL, "/") + "/.well-known/openid-configuration"
		p, err := openidConnect.New(o.ClientID, secret, o.CallbackURL, discovery, scopes...)
		if err != nil {
			return nil, fmt.Errorf("oidc provider (discovery %s): %w", discovery, err)
		}
		// goth's openidConnect.New names the provider "openid-connect" and
		// NewNamed("oidc") would mangle it to "oidc-oidc"; force the exact
		// name so gothic routes /auth/oidc[/callback] and the allowlist
		// subject is "oidc|<sub>".
		p.SetName("oidc")
		providers = append(providers, p)
		enabled = append(enabled, "oidc")
	}

	if o := cfg.OAuth.Okta; o != nil {
		secret, err := config.ReadSecretFile(o.ClientSecretFile)
		if err != nil {
			return nil, fmt.Errorf("okta secret: %w", err)
		}
		if o.ClientID == "" || o.OrgURL == "" || o.CallbackURL == "" {
			return nil, fmt.Errorf("okta provider requires client_id, org_url, callback_url")
		}
		providers = append(providers, okta.New(o.ClientID, secret, o.OrgURL, o.CallbackURL, "openid", "profile", "email"))
		enabled = append(enabled, "okta")
	}

	if g := cfg.OAuth.Google; g != nil {
		p, err := genericProvider("google", g, func(id, secret, cb string, scopes []string) goth.Provider {
			if len(scopes) == 0 {
				scopes = []string{"email", "profile"}
			}
			return google.New(id, secret, cb, scopes...)
		})
		if err != nil {
			return nil, err
		}
		providers = append(providers, p)
		enabled = append(enabled, "google")
	}

	if m := cfg.OAuth.Microsoft; m != nil {
		p, err := genericProvider("microsoft", m, func(id, secret, cb string, scopes []string) goth.Provider {
			return microsoftonline.New(id, secret, cb, scopes...)
		})
		if err != nil {
			return nil, err
		}
		providers = append(providers, p)
		// goth registers this provider under the name "microsoftonline"; the
		// config key is the shorter "microsoft" but the URL path uses goth's
		// internal name.
		enabled = append(enabled, "microsoftonline")
	}

	if f := cfg.OAuth.Facebook; f != nil {
		p, err := genericProvider("facebook", f, func(id, secret, cb string, scopes []string) goth.Provider {
			if len(scopes) == 0 {
				scopes = []string{"email"}
			}
			return facebook.New(id, secret, cb, scopes...)
		})
		if err != nil {
			return nil, err
		}
		providers = append(providers, p)
		enabled = append(enabled, "facebook")
	}

	if t := cfg.OAuth.Twitter; t != nil {
		// twitterv2 uses OAuth 1.0a against Twitter/X's v2 API and does not
		// take explicit scopes. The Scopes field on the config is ignored
		// for this provider.
		p, err := genericProvider("twitter", t, func(id, secret, cb string, _ []string) goth.Provider {
			return twitterv2.New(id, secret, cb)
		})
		if err != nil {
			return nil, err
		}
		providers = append(providers, p)
		enabled = append(enabled, "twitterv2")
	}

	// End-user claim provider (cross-auth federation). Registered with goth so
	// gothic can drive the /claim/* OIDC round-trip, but deliberately NOT added
	// to `enabled` — it is the end-user flow on the cooey brand, never an
	// operator login button. config.Load validated its fields when present.
	if cfg.Atproto != nil && cfg.Atproto.Claim != nil {
		o := cfg.Atproto.Claim
		secret, err := config.ReadSecretFile(o.ClientSecretFile)
		if err != nil {
			return nil, fmt.Errorf("claim oidc secret: %w", err)
		}
		scopes := o.Scopes
		if len(scopes) == 0 {
			scopes = []string{"openid", "profile", "email"}
		}
		discovery := strings.TrimRight(o.IssuerURL, "/") + "/.well-known/openid-configuration"
		p, err := openidConnect.New(o.ClientID, secret, o.CallbackURL, discovery, scopes...)
		if err != nil {
			return nil, fmt.Errorf("claim oidc provider (discovery %s): %w", discovery, err)
		}
		p.SetName("claim")
		providers = append(providers, p)
	}

	if len(providers) == 0 {
		return nil, fmt.Errorf("no OAuth providers configured")
	}
	goth.UseProviders(providers...)
	return enabled, nil
}

func genericProvider(label string, p *config.GenericProvider, build func(id, secret, cb string, scopes []string) goth.Provider) (goth.Provider, error) {
	if p.ClientID == "" || p.CallbackURL == "" {
		return nil, fmt.Errorf("%s provider requires client_id and callback_url", label)
	}
	secret, err := config.ReadSecretFile(p.ClientSecretFile)
	if err != nil {
		return nil, fmt.Errorf("%s secret: %w", label, err)
	}
	return build(p.ClientID, secret, p.CallbackURL, p.Scopes), nil
}
