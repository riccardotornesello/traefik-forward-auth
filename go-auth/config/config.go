package config

import (
	"os"
	"strings"
)

type Config struct {
	Secret  string
	BaseURL string

	OidcIssuer       string
	OidcClientID     string
	OidcClientSecret string
	OidcScopes       []string

	AuthDuration int64

	AllowedEmailDomains []string
}

var (
	config *Config
)

func GetConfig() *Config {
	if config == nil {
		config = &Config{
			Secret:  os.Getenv("SECRET"),
			BaseURL: os.Getenv("BASE_URL"),

			OidcIssuer:       os.Getenv("OIDC_ISSUER"),
			OidcClientID:     os.Getenv("OIDC_CLIENT_ID"),
			OidcClientSecret: os.Getenv("OIDC_CLIENT_SECRET"),
			OidcScopes:       []string{"openid", "profile", "email"},

			AuthDuration: 7 * 24 * 60 * 60,

			AllowedEmailDomains: strings.Split(os.Getenv("ALLOWED_EMAIL_DOMAINS"), ","),
		}
	}

	return config
}
