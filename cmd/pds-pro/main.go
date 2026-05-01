package main

import (
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/P3X-118/pds-pro/internal/audit"
	"github.com/P3X-118/pds-pro/internal/auth"
	"github.com/P3X-118/pds-pro/internal/config"
	"github.com/P3X-118/pds-pro/internal/handlers"
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

	tpls, err := loadTemplates(*templateDir)
	if err != nil {
		log.Fatalf("templates: %v", err)
	}

	srv := handlers.New(cfg, tpls, sm, al, providers)

	log.Printf("listening on %s (providers: %v, instances: %d)", cfg.ListenAddr, providers, len(cfg.Instances))
	if err := http.ListenAndServe(cfg.ListenAddr, srv.Routes()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
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
