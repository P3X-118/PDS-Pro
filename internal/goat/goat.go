package goat

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/P3X-118/sgc-pds-admin/internal/config"
)

type Client struct {
	binary   string
	instance *config.PDSInstance
	password string
}

func NewClient(binary string, instance *config.PDSInstance) (*Client, error) {
	pw, err := config.ReadSecretFile(instance.AdminPasswordFile)
	if err != nil {
		return nil, err
	}
	if binary == "" {
		binary = "goat"
	}
	return &Client{binary: binary, instance: instance, password: pw}, nil
}

type Account struct {
	DID    string `json:"did"`
	Status string `json:"status"`
	Rev    string `json:"rev"`
}

func (c *Client) AccountList(ctx context.Context) ([]Account, error) {
	out, err := c.run(ctx, "pds", "admin", "account", "list")
	if err != nil {
		return nil, err
	}
	var accounts []Account
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, "\t")
		if len(fields) < 3 {
			continue
		}
		accounts = append(accounts, Account{DID: fields[0], Status: fields[1], Rev: fields[2]})
	}
	return accounts, scanner.Err()
}

type CreateAccountInput struct {
	Handle      string
	Email       string
	Password    string
	ExistingDID string
	RecoveryKey string
}

func (c *Client) AccountCreate(ctx context.Context, in CreateAccountInput) (string, error) {
	args := []string{"pds", "admin", "account", "create",
		"--handle", in.Handle,
		"--email", in.Email,
		"--password", in.Password,
	}
	if in.ExistingDID != "" {
		args = append(args, "--existing-did", in.ExistingDID)
	}
	if in.RecoveryKey != "" {
		args = append(args, "--recovery-key", in.RecoveryKey)
	}
	out, err := c.run(ctx, args...)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func (c *Client) AccountTakedown(ctx context.Context, user string, reverse bool) error {
	args := []string{"pds", "admin", "account", "takedown"}
	if reverse {
		args = append(args, "--reverse")
	}
	args = append(args, user)
	_, err := c.run(ctx, args...)
	return err
}

func (c *Client) AccountInfo(ctx context.Context, user string) (json.RawMessage, error) {
	out, err := c.run(ctx, "pds", "admin", "account", "info", user)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(out), nil
}

func (c *Client) AccountDelete(ctx context.Context, user string) error {
	_, err := c.run(ctx, "pds", "admin", "account", "delete", user)
	return err
}

func (c *Client) AccountResetPassword(ctx context.Context, user string) (string, error) {
	out, err := c.run(ctx, "pds", "admin", "account", "reset-password", user)
	if err != nil {
		return "", err
	}
	// goat prints "new password: <pw>"
	line := strings.TrimSpace(string(out))
	if i := strings.LastIndex(line, ": "); i != -1 {
		return strings.TrimSpace(line[i+2:]), nil
	}
	return line, nil
}

type UpdateAccountInput struct {
	Email  string
	Handle string
}

func (c *Client) AccountUpdate(ctx context.Context, user string, in UpdateAccountInput) ([]byte, error) {
	args := []string{"pds", "admin", "account", "update"}
	if in.Email != "" {
		args = append(args, "--email", in.Email)
	}
	if in.Handle != "" {
		args = append(args, "--handle", in.Handle)
	}
	args = append(args, user)
	return c.run(ctx, args...)
}

func (c *Client) BlobStatus(ctx context.Context, user, cid string) (json.RawMessage, error) {
	out, err := c.run(ctx, "pds", "admin", "blob", "status", user, cid)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(out), nil
}

func (c *Client) BlobPurge(ctx context.Context, user, cid string, reverse bool) error {
	args := []string{"pds", "admin", "blob", "purge"}
	if reverse {
		args = append(args, "--reverse")
	}
	args = append(args, user, cid)
	_, err := c.run(ctx, args...)
	return err
}

func (c *Client) CreateInvites(ctx context.Context, count, uses int) ([]string, error) {
	if count < 1 {
		count = 1
	}
	if uses < 1 {
		uses = 1
	}
	out, err := c.run(ctx, "pds", "admin", "create-invites",
		"--count", fmt.Sprintf("%d", count),
		"--uses", fmt.Sprintf("%d", uses),
	)
	if err != nil {
		return nil, err
	}
	var codes []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			codes = append(codes, line)
		}
	}
	return codes, nil
}

func (c *Client) run(ctx context.Context, args ...string) ([]byte, error) {
	if len(args) < 3 || args[0] != "pds" || args[1] != "admin" {
		return nil, fmt.Errorf("goat: expected args starting with \"pds admin\"")
	}
	full := []string{"pds", "admin", "--admin-password", c.password, "--pds-host", c.instance.PDSHost}
	full = append(full, args[2:]...)
	cmd := exec.CommandContext(ctx, c.binary, full...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("goat %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}
