// Package atproto is a tiny XRPC client for the few com.atproto.server calls the
// pds-pro session broker needs: create a session from the managed password, and
// mint a revocable app-password for external Bluesky clients. pds-pro can do
// this on a user's behalf because it set (and can re-derive) the account's
// managed password — see internal/linkage.
package atproto

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

var httpClient = &http.Client{Timeout: 15 * time.Second}

// Session is the result of com.atproto.server.createSession.
type Session struct {
	AccessJwt  string `json:"accessJwt"`
	RefreshJwt string `json:"refreshJwt"`
	DID        string `json:"did"`
	Handle     string `json:"handle"`
}

func post(ctx context.Context, pdsHost, nsid, bearer string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	endpoint := strings.TrimRight(pdsHost, "/") + "/xrpc/" + nsid
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("atproto %s: %s", nsid, resp.Status)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// CreateSession logs in with identifier (handle or DID) + password.
func CreateSession(ctx context.Context, pdsHost, identifier, password string) (*Session, error) {
	var s Session
	err := post(ctx, pdsHost, "com.atproto.server.createSession", "",
		map[string]string{"identifier": identifier, "password": password}, &s)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// ResolveHandle returns the DID the PDS has registered for a handle (via the
// public com.atproto.identity.resolveHandle), or an error if the handle is not
// hosted there. Used to RECOVER a pre-existing account whose link-back never
// completed: provisioning sees "handle already taken", resolves the DID here,
// and links it back instead of failing forever.
func ResolveHandle(ctx context.Context, pdsHost, handle string) (string, error) {
	endpoint := strings.TrimRight(pdsHost, "/") + "/xrpc/com.atproto.identity.resolveHandle?handle=" + url.QueryEscape(handle)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("atproto resolveHandle %s: %s", handle, resp.Status)
	}
	var out struct {
		DID string `json:"did"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if out.DID == "" {
		return "", fmt.Errorf("atproto resolveHandle %s: empty did", handle)
	}
	return out.DID, nil
}

// AdminUpdateHandle re-asserts an account's handle using PDS admin auth
// (com.atproto.admin.updateAccountHandle). Unlike an account-authed updateHandle
// it needs no user session — so it works regardless of the account's (possibly
// stale) managed password — and it reliably sequences a fresh #identity event on
// the firehose, which prompts the relay/AppView to re-resolve the handle. That is
// the nudge that clears `handle.invalid` once the account's `_atproto` TXT exists
// (the AppView caches a failed resolution until the next identity event).
func AdminUpdateHandle(ctx context.Context, pdsHost, adminPassword, did, handle string) error {
	b, err := json.Marshal(map[string]string{"did": did, "handle": handle})
	if err != nil {
		return err
	}
	endpoint := strings.TrimRight(pdsHost, "/") + "/xrpc/com.atproto.admin.updateAccountHandle"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("admin", adminPassword)
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("atproto admin updateAccountHandle: %s", resp.Status)
	}
	return nil
}

// appViewBase is the public bsky AppView read endpoint. getProfile here returns
// the handle the AppView has *verified* for a DID (or "handle.invalid" if it has
// not), which is what we use to decide whether an account still needs an identity
// nudge.
const appViewBase = "https://public.api.bsky.app"

// AppViewHandle returns the handle the bsky AppView currently verifies for a DID
// via app.bsky.actor.getProfile. It returns "handle.invalid" when the AppView
// cannot bidirectionally verify the handle yet. Used to detect accounts that
// still need an identity nudge after their _atproto TXT is in place.
func AppViewHandle(ctx context.Context, did string) (string, error) {
	endpoint := appViewBase + "/xrpc/app.bsky.actor.getProfile?actor=" + url.QueryEscape(did)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("atproto getProfile %s: %s", did, resp.Status)
	}
	var out struct {
		Handle string `json:"handle"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.Handle, nil
}

// CreateAppPassword mints a named, revocable app-password using an active
// session's access JWT. Returns the generated password (shown to the user once).
func CreateAppPassword(ctx context.Context, pdsHost, accessJwt, name string) (string, error) {
	var out struct {
		Password string `json:"password"`
	}
	err := post(ctx, pdsHost, "com.atproto.server.createAppPassword", accessJwt,
		map[string]string{"name": name}, &out)
	if err != nil {
		return "", err
	}
	return out.Password, nil
}
