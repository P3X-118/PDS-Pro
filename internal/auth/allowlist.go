package auth

import (
	"strings"

	"github.com/P3X-118/pds-pro/internal/config"
)

type Decision struct {
	Allowed bool
	Roles   []string
}

func Authorize(entries []config.AllowEntry, subject, email string) Decision {
	emailLower := strings.ToLower(email)
	for _, e := range entries {
		if e.Subject != "" && e.Subject == subject {
			return Decision{Allowed: true, Roles: e.Roles}
		}
		if e.Email != "" && strings.EqualFold(e.Email, email) {
			return Decision{Allowed: true, Roles: e.Roles}
		}
		if e.EmailDomain != "" && emailLower != "" {
			at := strings.LastIndex(emailLower, "@")
			if at != -1 && strings.EqualFold(emailLower[at+1:], e.EmailDomain) {
				return Decision{Allowed: true, Roles: e.Roles}
			}
		}
	}
	return Decision{Allowed: false}
}

func HasRole(roles []string, want string) bool {
	for _, r := range roles {
		if r == want {
			return true
		}
	}
	return false
}
