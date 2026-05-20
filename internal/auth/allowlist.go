package auth

import (
	"strings"

	"github.com/P3X-118/pds-pro/internal/config"
)

type Decision struct {
	Allowed   bool
	Roles     []string
	Instances []string
}

func Authorize(entries []config.AllowEntry, subject, email string) Decision {
	emailLower := strings.ToLower(email)
	for _, e := range entries {
		if e.Subject != "" && e.Subject == subject {
			return Decision{Allowed: true, Roles: e.Roles, Instances: e.Instances}
		}
		if e.Email != "" && strings.EqualFold(e.Email, email) {
			return Decision{Allowed: true, Roles: e.Roles, Instances: e.Instances}
		}
		if e.EmailDomain != "" && emailLower != "" {
			at := strings.LastIndex(emailLower, "@")
			if at != -1 && strings.EqualFold(emailLower[at+1:], e.EmailDomain) {
				return Decision{Allowed: true, Roles: e.Roles, Instances: e.Instances}
			}
		}
	}
	return Decision{Allowed: false}
}

// CanAccessInstance is the single authorization chokepoint for per-instance
// access. Deny by default: only the "super-admin" role (all instances) or an
// identity explicitly scoped to name may proceed.
func CanAccessInstance(roles, instances []string, name string) bool {
	if name == "" {
		return false
	}
	if HasRole(roles, "super-admin") {
		return true
	}
	for _, i := range instances {
		if i == name {
			return true
		}
	}
	return false
}

func HasRole(roles []string, want string) bool {
	for _, r := range roles {
		if r == want {
			return true
		}
	}
	return false
}
