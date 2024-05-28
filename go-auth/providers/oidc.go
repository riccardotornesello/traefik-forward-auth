package providers

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"traefikauth.riccardotornesello.it/config"
)

func InitializeOidcProvider(group string, next string) rp.RelyingParty {
	config := config.GetConfig()

	params := url.Values{
		"next":  {next},
		"group": {group},
	}

	callbackUr, err := url.JoinPath(config.BaseURL, "/callback")
	if err != nil {
		logrus.Fatalf("error creating callback url %s", err.Error())
	}
	redirectURI := fmt.Sprintf("%s?%s", callbackUr, params.Encode())

	httpClient := &http.Client{
		Timeout: time.Second * 10,
	}
	oidcOptions := []rp.Option{
		rp.WithVerifierOpts(rp.WithIssuedAtOffset(10 * time.Second)),
		rp.WithHTTPClient(httpClient),
	}
	ctx := context.TODO()
	oidcProvider, err := rp.NewRelyingPartyOIDC(ctx, config.OidcIssuer, config.OidcClientID, config.OidcClientSecret, redirectURI, config.OidcScopes, oidcOptions...)
	if err != nil {
		logrus.Fatalf("error creating provider %s", err.Error())
	}

	return oidcProvider
}
