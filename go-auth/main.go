package main

import (
	"net/http"
	"os"

	"github.com/sirupsen/logrus"
	"traefikauth.riccardotornesello.it/handlers"
)

func main() {
	http.HandleFunc("/callback", handlers.CallbackHandler)
	http.HandleFunc("/", handlers.CheckAuthenticationHandler)

	lis := "0.0.0.0:3000"

	logrus.Info("server listening, press ctrl+c to stop. Listening on: ", lis)

	err := http.ListenAndServe(lis, nil)
	if err != http.ErrServerClosed {
		logrus.Error("server terminated. Error: ", err)
		os.Exit(1)
	}
}
