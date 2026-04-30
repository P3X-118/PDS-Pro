package goat

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// RequestCrawl asks a relay to crawl the given PDS hostname. This is a
// public XRPC call; no admin auth required. Goat does not ship this
// command, so we make the HTTP call directly.
func RequestCrawl(ctx context.Context, relayURL, pdsHostname string) error {
	u, err := url.Parse(relayURL)
	if err != nil {
		return fmt.Errorf("relay url: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("relay url must include scheme and host")
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/xrpc/com.atproto.sync.requestCrawl"
	body, _ := json.Marshal(map[string]string{"hostname": pdsHostname})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("relay returned %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}
