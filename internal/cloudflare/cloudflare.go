// Package cloudflare is a minimal Cloudflare DNS API client scoped to a single
// zone. pds-pro uses it to publish the `_atproto.<handle>` TXT records that make
// a provisioned `<user>.<handle_domain>` handle resolvable to its DID. Without
// that record the bsky AppView cannot bidirectionally verify the handle and
// shows the account as `handle.invalid`, so publishing it is part of making a
// new account externally usable. The API token needs Zone:DNS:Edit on the zone.
package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const apiBase = "https://api.cloudflare.com/client/v4"

// Client talks to the Cloudflare v4 API for one named zone. The zone id is
// resolved lazily from the zone name and cached.
type Client struct {
	token    string
	zoneName string
	http     *http.Client

	mu     sync.Mutex
	zoneID string
}

// New returns a client for zoneName (e.g. "cooey.club") authenticated with a
// Zone:DNS:Edit API token.
func New(token, zoneName string) *Client {
	return &Client{
		token:    strings.TrimSpace(token),
		zoneName: strings.TrimSpace(zoneName),
		http:     &http.Client{Timeout: 15 * time.Second},
	}
}

type apiResp struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result json.RawMessage `json:"result"`
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, apiBase+path, r)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var ar apiResp
	if err := json.Unmarshal(raw, &ar); err != nil {
		return fmt.Errorf("cloudflare %s %s: status %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if !ar.Success {
		msg := "request failed"
		if len(ar.Errors) > 0 {
			msg = ar.Errors[0].Message
		}
		return fmt.Errorf("cloudflare %s %s: %s", method, path, msg)
	}
	if out != nil && len(ar.Result) > 0 {
		return json.Unmarshal(ar.Result, out)
	}
	return nil
}

func (c *Client) zone(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.zoneID != "" {
		return c.zoneID, nil
	}
	if c.zoneName == "" {
		return "", fmt.Errorf("cloudflare: zone_name not configured")
	}
	var zones []struct {
		ID string `json:"id"`
	}
	if err := c.do(ctx, http.MethodGet, "/zones?name="+url.QueryEscape(c.zoneName), nil, &zones); err != nil {
		return "", err
	}
	if len(zones) == 0 {
		return "", fmt.Errorf("cloudflare: zone %q not found (token scope?)", c.zoneName)
	}
	c.zoneID = zones[0].ID
	return c.zoneID, nil
}

type dnsRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
}

// UpsertTXT ensures a single TXT record `name` holds exactly `content`. It
// returns changed=true when it had to create or rewrite the record (the zone did
// not already hold the correct value), so the caller can trigger dependent work
// (e.g. an atproto identity event) only when something actually moved. It is a
// no-op — changed=false — when the record is already correct, so it is safe to
// call on every reconcile pass. A short TTL keeps handle-resolution fixes fast.
func (c *Client) UpsertTXT(ctx context.Context, name, content string) (bool, error) {
	zoneID, err := c.zone(ctx)
	if err != nil {
		return false, err
	}
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")

	var recs []dnsRecord
	if err := c.do(ctx, http.MethodGet,
		fmt.Sprintf("/zones/%s/dns_records?type=TXT&name=%s", zoneID, url.QueryEscape(name)),
		nil, &recs); err != nil {
		return false, err
	}

	rec := map[string]any{"type": "TXT", "name": name, "content": content, "ttl": 120}
	for _, r := range recs {
		// Cloudflare may return TXT content with surrounding quotes.
		if strings.Trim(r.Content, "\"") == content {
			return false, nil
		}
		// A record exists with the wrong value (e.g. a re-provisioned account got
		// a new DID) — rewrite it in place.
		if err := c.do(ctx, http.MethodPut, "/zones/"+zoneID+"/dns_records/"+r.ID, rec, nil); err != nil {
			return false, err
		}
		return true, nil
	}

	if err := c.do(ctx, http.MethodPost, "/zones/"+zoneID+"/dns_records", rec, nil); err != nil {
		return false, err
	}
	return true, nil
}
