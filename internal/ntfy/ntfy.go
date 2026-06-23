// Package ntfy is a tiny ntfy publisher for operator alerts — e.g. an atproto
// provisioning failure that a human (or the reconciler) needs to follow up on.
// Alerting is best-effort and must never block or fail the caller's primary
// flow; an unconfigured Client is a silent no-op.
package ntfy

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	url   string // baseURL/topic, empty when unconfigured
	token string
	http  *http.Client
}

// New returns a publisher for baseURL + topic. token is optional (bearer auth
// for protected topics). If baseURL or topic is empty the publisher is a no-op.
func New(baseURL, topic, token string) *Client {
	if baseURL == "" || topic == "" {
		return &Client{}
	}
	return &Client{
		url:   strings.TrimRight(baseURL, "/") + "/" + topic,
		token: token,
		http:  &http.Client{Timeout: 10 * time.Second},
	}
}

// Publish posts a notification. Errors are returned for logging but callers
// should treat alerting as best-effort and never fail their flow on a non-nil
// return.
func (c *Client) Publish(ctx context.Context, title, message string, priority int, tags string) error {
	if c == nil || c.url == "" {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, strings.NewReader(message))
	if err != nil {
		return err
	}
	if title != "" {
		req.Header.Set("X-Title", title)
	}
	if priority > 0 {
		req.Header.Set("X-Priority", strconv.Itoa(priority))
	}
	if tags != "" {
		req.Header.Set("X-Tags", tags)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("ntfy: publish %s: %s", c.url, resp.Status)
	}
	return nil
}
