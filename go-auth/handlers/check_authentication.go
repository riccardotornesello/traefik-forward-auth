package handlers

import (
	"net/http"

	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"traefikauth.riccardotornesello.it/auth"
	"traefikauth.riccardotornesello.it/providers"
)

func redirectToLogin(w http.ResponseWriter, r *http.Request) {
	proto := r.Header.Get("X-Forwarded-Proto")
	host := r.Header.Get("X-Forwarded-Host")
	uri := r.Header.Get("X-Forwarded-Uri")
	next := proto + "://" + host + uri

	group := r.URL.Query().Get("group")

	oidcProvider := providers.InitializeOidcProvider(group, next)

	authUrl := rp.AuthURL(
		"",
		oidcProvider,
	)

	http.Redirect(w, r, authUrl, http.StatusFound)
}

func CheckAuthenticationHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	cookie, err := r.Cookie("traefikauth")
	if err != nil {
		redirectToLogin(w, r)
		return
	}

	tokenString := cookie.Value
	email, groupsDirect, err := providers.ParseJWT(tokenString)
	if err != nil {
		redirectToLogin(w, r)
		return
	}

	IsAuthenticated := auth.IsAuthenticated(r, email, groupsDirect)
	if IsAuthenticated {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("You are authenticated"))
		return
	} else {
		redirectToLogin(w, r)
		return
	}
}
