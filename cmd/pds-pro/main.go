package main

import (
	"context"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/P3X-118/pds-pro/internal/audit"
	"github.com/P3X-118/pds-pro/internal/auth"
	"github.com/P3X-118/pds-pro/internal/authentik"
	"github.com/P3X-118/pds-pro/internal/config"
	"github.com/P3X-118/pds-pro/internal/handlers"
	"github.com/P3X-118/pds-pro/internal/linkage"
	"github.com/P3X-118/pds-pro/internal/ntfy"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to config.yaml")
	templateDir := flag.String("templates", "web/templates", "template directory")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	sm, err := auth.NewManager(cfg.Session.SecretFile, cfg.Session.Secure, cfg.Session.MaxAgeSec)
	if err != nil {
		log.Fatalf("session: %v", err)
	}

	providers, err := auth.RegisterProviders(cfg, sm)
	if err != nil {
		log.Fatalf("oauth: %v", err)
	}

	al, err := audit.New(cfg.Audit.DBPath, cfg.Audit.LogPath)
	if err != nil {
		log.Fatalf("audit: %v", err)
	}
	defer al.Close()

	// Cross-auth federation (optional): the management-plane service that
	// provisions <handle>.cooey.club accounts and links them onto Authentik
	// users. config.Load already validated the dependent blocks are present.
	// Run() sweeps every user (source-agnostic: Discord/chat/bsky) on a periodic
	// tick AND on each webhook Kick().
	link := buildLinkage(cfg, al)
	if link != nil {
		go link.Run(context.Background(), 2*time.Minute)
	}

	hookSecret := ""
	if cfg.Atproto != nil && cfg.Atproto.WebhookSecretFile != "" {
		if hookSecret, err = config.ReadSecretFile(cfg.Atproto.WebhookSecretFile); err != nil {
			log.Fatalf("atproto webhook secret: %v", err)
		}
	}

	tpls, err := loadTemplates(*templateDir)
	if err != nil {
		log.Fatalf("templates: %v", err)
	}

	srv := handlers.New(cfg, tpls, sm, al, providers, link, hookSecret)

	log.Printf("listening on %s (providers: %v, instances: %d, atproto: %t)", cfg.ListenAddr, providers, len(cfg.Instances), link != nil)
	if err := http.ListenAndServe(cfg.ListenAddr, srv.Routes()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// buildLinkage constructs the atproto linkage service from config, or returns
// nil if the federation is not configured. Secret-file reads are fatal because
// a misconfigured-but-present atproto block is an operator error, not a
// degrade-gracefully condition.
func buildLinkage(cfg *config.Config, al audit.Logger) *linkage.Service {
	if cfg.Atproto == nil {
		return nil
	}
	akToken, err := config.ReadSecretFile(cfg.Authentik.TokenFile)
	if err != nil {
		log.Fatalf("authentik token: %v", err)
	}
	managedSecret, err := config.ReadSecretFile(cfg.Atproto.ManagedPasswordSecretFile)
	if err != nil {
		log.Fatalf("atproto managed secret: %v", err)
	}
	nc := ntfy.New("", "", "")
	if cfg.Ntfy != nil {
		var ntfyToken string
		if cfg.Ntfy.TokenFile != "" {
			if ntfyToken, err = config.ReadSecretFile(cfg.Ntfy.TokenFile); err != nil {
				log.Fatalf("ntfy token: %v", err)
			}
		}
		nc = ntfy.New(cfg.Ntfy.BaseURL, cfg.Ntfy.Topic, ntfyToken)
	}
	akc := authentik.NewClient(cfg.Authentik.BaseURL, akToken)
	return linkage.NewService(cfg, akc, nc, al, managedSecret)
}

func loadTemplates(dir string) (handlers.Templates, error) {
	layout := filepath.Join(dir, "layout.html")
	pages, err := filepath.Glob(filepath.Join(dir, "*.html"))
	if err != nil {
		return nil, err
	}
	out := handlers.Templates{}
	for _, p := range pages {
		name := filepath.Base(p)
		if name == "layout.html" {
			continue
		}
		t, err := template.ParseFiles(layout, p)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", p, err)
		}
		out[name] = t
	}
	return out, nil
}
