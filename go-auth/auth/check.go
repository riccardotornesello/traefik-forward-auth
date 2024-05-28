package auth

import (
	"net/http"
	"strings"

	"traefikauth.riccardotornesello.it/config"
)

func IsAuthenticated(r *http.Request, email string, groupsDirect []string) bool {
	config := config.GetConfig()

	at := strings.LastIndex(email, "@")
	if at == -1 {
		return false
	}
	domain := email[at+1:]
	allowedEmail := false
	for _, allowedDomain := range config.AllowedEmailDomains {
		if domain == allowedDomain {
			allowedEmail = true
			break
		}
	}
	if allowedEmail {
		return true
	}

	queryGroup := r.URL.Query().Get("group")
	for _, group := range groupsDirect {
		if group == queryGroup {
			return true
		}
		if strings.HasPrefix(group, queryGroup+"/") {
			return true
		}
	}

	return false
}
