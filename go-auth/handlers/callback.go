package handlers

import (
	"net/http"
	"strings"
	"time"

	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"traefikauth.riccardotornesello.it/auth"
	"traefikauth.riccardotornesello.it/config"
	"traefikauth.riccardotornesello.it/providers"
)

func CallbackHandler(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	group := r.URL.Query().Get("group")

	oidcProvider := providers.InitializeOidcProvider(group, next)
	config := config.GetConfig()

	tokens, err := rp.CodeExchange[*oidc.IDTokenClaims](
		r.Context(),
		r.URL.Query().Get("code"),
		oidcProvider,
	)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// TODO: Instead of the JWT, we should allow to use an in memory session

	tokenString, err := providers.CreateJWT(tokens.IDTokenClaims.Claims["email"].(string), tokens.IDTokenClaims.Claims["groups_direct"].([]interface{}))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "traefikauth",
		Value:    tokenString,
		Expires:  time.Now().Add(time.Second * time.Duration(config.AuthDuration)),
		Path:     "/",
		Domain:   strings.Split(r.Host, ":")[0],
		HttpOnly: true,
	})

	email := tokens.IDTokenClaims.Claims["email"].(string)
	groupsDirect := tokens.IDTokenClaims.Claims["groups_direct"].([]interface{})
	groupsDirectStrings := make([]string, len(groupsDirect))
	for i, v := range groupsDirect {
		groupsDirectStrings[i] = v.(string)
	}

	IsAuthenticated := auth.IsAuthenticated(r, email, groupsDirectStrings)

	if IsAuthenticated {
		http.Redirect(w, r, r.URL.Query().Get("next"), http.StatusFound)
	} else {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}
}
