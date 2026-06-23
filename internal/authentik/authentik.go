// Package authentik is a minimal Authentik API client for the pds-pro
// management plane: resolve a user (by username or email) and write their
// linked atproto identity onto attributes.atproto.{did,handle,status}. It uses
// the svc-pds-pro-atproto-writer API token (view_user + change_user), so it can
// look users up and edit their attributes but not create or delete them.
package authentik

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

func NewClient(baseURL, token string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		http:    &http.Client{Timeout: 15 * time.Second},
	}
}

// User is the subset of the Authentik core user we care about.
type User struct {
	PK         int            `json:"pk"`
	Username   string         `json:"username"`
	Email      string         `json:"email"`
	Type       string         `json:"type"` // internal | external | service_account | internal_service_account
	Attributes map[string]any `json:"attributes"`
}

// Provisionable reports whether this user should get an atproto account: real
// humans (internal/external) with a username, never the service accounts (e.g.
// svc-pds-pro-atproto-writer) that exist only to drive the API.
func (u *User) Provisionable() bool {
	switch u.Type {
	case "service_account", "internal_service_account":
		return false
	}
	return strings.TrimSpace(u.Username) != ""
}

// Atproto is the linkage record pds-pro stores under attributes.atproto. It is
// also the shape the OIDC `atproto` claim mapping reads back out.
type Atproto struct {
	DID    string `json:"did,omitempty"`
	Handle string `json:"handle,omitempty"`
	Status string `json:"status"`          // "active" | "error"
	Error  string `json:"error,omitempty"` // populated when status=="error"
	PDS    string `json:"pds,omitempty"`   // the PDS host that issued the DID
	Sub    string `json:"sub,omitempty"`   // OIDC subject, so the reconciler can re-derive the managed password
}

// Lookup identifies a user. The first non-empty field (username, then email) is
// used as an exact-match query.
type Lookup struct {
	Username string
	Email    string
}

func (c *Client) do(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var rdr *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.http.Do(req)
}

// FindUser resolves a single user by the given Lookup. It is an error if zero
// or more than one user matches — an ambiguous identity must never silently
// resolve to an arbitrary account.
func (c *Client) FindUser(ctx context.Context, l Lookup) (*User, error) {
	q := url.Values{}
	switch {
	case l.Username != "":
		q.Set("username", l.Username)
	case l.Email != "":
		q.Set("email", l.Email)
	default:
		return nil, fmt.Errorf("authentik: empty user lookup")
	}
	resp, err := c.do(ctx, http.MethodGet, "/api/v3/core/users/?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("authentik: list users %s: %s", q.Encode(), resp.Status)
	}
	var out struct {
		Results []User `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	if len(out.Results) == 0 {
		return nil, fmt.Errorf("authentik: no user for %s", q.Encode())
	}
	if len(out.Results) > 1 {
		return nil, fmt.Errorf("authentik: %d users for %s (ambiguous)", len(out.Results), q.Encode())
	}
	return &out.Results[0], nil
}

// ListUsers returns users, optionally narrowed to a single group by name
// (groups_by_name). It follows Authentik's page-number pagination. An empty
// groupName lists all users (callers on a shared Authentik must scope).
func (c *Client) ListUsers(ctx context.Context, groupName string) ([]User, error) {
	var filter string
	if groupName != "" {
		filter = "&groups_by_name=" + url.QueryEscape(groupName)
	}
	var users []User
	for page := 1; page > 0; {
		resp, err := c.do(ctx, http.MethodGet, fmt.Sprintf("/api/v3/core/users/?page_size=100&page=%d%s", page, filter), nil)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, fmt.Errorf("authentik: list users: %s", resp.Status)
		}
		var out struct {
			Pagination struct {
				Next int `json:"next"`
			} `json:"pagination"`
			Results []User `json:"results"`
		}
		err = json.NewDecoder(resp.Body).Decode(&out)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		users = append(users, out.Results...)
		page = out.Pagination.Next // 0 ends the loop
	}
	return users, nil
}

// Atproto parses the user's stored attributes.atproto into a typed record, or
// nil if absent/unparseable.
func (u *User) Atproto() *Atproto {
	raw, ok := u.Attributes["atproto"]
	if !ok || raw == nil {
		return nil
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return nil
	}
	var a Atproto
	if err := json.Unmarshal(b, &a); err != nil {
		return nil
	}
	return &a
}

// SetAtproto merges the atproto record into the user's attributes and PATCHes
// the whole attributes object back. Authentik replaces `attributes` wholesale
// on PATCH (no deep-merge), so we read-modify-write to avoid clobbering other
// keys the user may carry.
func (c *Client) SetAtproto(ctx context.Context, u *User, a Atproto) error {
	attrs := u.Attributes
	if attrs == nil {
		attrs = map[string]any{}
	}
	attrs["atproto"] = a
	resp, err := c.do(ctx, http.MethodPatch, fmt.Sprintf("/api/v3/core/users/%d/", u.PK), map[string]any{"attributes": attrs})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("authentik: patch user %d: %s", u.PK, resp.Status)
	}
	// Keep the in-memory copy consistent for any subsequent use.
	u.Attributes = attrs
	return nil
}
