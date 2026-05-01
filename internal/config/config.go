package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ListenAddr string         `yaml:"listen_addr"`
	BaseURL    string         `yaml:"base_url"`
	Session    SessionConfig  `yaml:"session"`
	OAuth      OAuthConfig    `yaml:"oauth"`
	Allowlist  []AllowEntry   `yaml:"allowlist"`
	Instances  []PDSInstance  `yaml:"instances"`
	Audit      AuditConfig    `yaml:"audit"`
	Goat       GoatConfig     `yaml:"goat"`
}

type SessionConfig struct {
	SecretFile string `yaml:"secret_file"`
	Secure     bool   `yaml:"secure"`
	MaxAgeSec  int    `yaml:"max_age_sec"`
}

type OAuthConfig struct {
	Okta      *OktaProvider    `yaml:"okta,omitempty"`
	Google    *GenericProvider `yaml:"google,omitempty"`
	Microsoft *GenericProvider `yaml:"microsoft,omitempty"`
	Facebook  *GenericProvider `yaml:"facebook,omitempty"`
	Twitter   *GenericProvider `yaml:"twitter,omitempty"`
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
	if c.OAuth.Okta == nil && c.OAuth.Google == nil && c.OAuth.Microsoft == nil && c.OAuth.Facebook == nil && c.OAuth.Twitter == nil {
		return nil, fmt.Errorf("at least one OAuth provider must be configured")
	}
	if len(c.Instances) == 0 {
		return nil, fmt.Errorf("at least one PDS instance must be configured")
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
