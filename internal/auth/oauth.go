package auth

import (
	"fmt"

	"github.com/P3X-118/pds-pro/internal/config"
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/okta"
)

func RegisterProviders(cfg *config.Config) ([]string, error) {
	var enabled []string
	providers := make([]goth.Provider, 0, 1)

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

	if len(providers) == 0 {
		return nil, fmt.Errorf("no OAuth providers configured")
	}
	goth.UseProviders(providers...)
	return enabled, nil
}
