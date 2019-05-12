package main

import (
	"fmt"
	"net/http"

	"github.com/roberveral/oauth-server/config"

	"github.com/gorilla/mux"
	"github.com/roberveral/oauth-server/api"
	"github.com/roberveral/oauth-server/api/auth"
	log "github.com/sirupsen/logrus"
)

const apiVersion = "/v0"

func main() {
	log.Info("OAuth Authorization Server - Starting...")

	conf, err := config.Load()
	if err != nil {
		log.Fatal("Invalid configuration: ", err)
		return
	}

	if conf.Debug {
		log.SetLevel(log.DebugLevel)
	}

	store, err := conf.Mongo.Store()
	if err != nil {
		log.Fatal("Unable to create Mongo connector: ", err)
		return
	}
	rsaKey, err := conf.OAuth.RSAKey()
	if err != nil {
		log.Fatal("Unable to generate key pair: ", err)
		return
	}
	tokenProvider, err := conf.OAuth.TokenProvider(rsaKey)
	if err != nil {
		log.Fatal("Unable to create Token Provider: ", err)
		return
	}

	idp, err := conf.Ldap.IdentityProvider()
	if err != nil {
		log.Fatal("Unable to create LDAP connector: ", err)
		return
	}

	oauthManager := conf.OAuth.Manager(idp, store, tokenProvider)

	cors := conf.API.Cors(conf.Debug)

	authentication, err := conf.API.Authentication()
	if err != nil {
		log.Fatal("Unable to configure API authentication: ", err)
		return
	}

	jwks, err := tokenProvider.GetJwks()
	if err != nil {
		log.Fatal("Unable to prepare JWK set: ", err)
		return
	}

	// Instantiate HTTP request router
	r := mux.NewRouter()
	ar := r.PathPrefix(apiVersion).Subrouter()
	uar := r.PathPrefix(apiVersion).Subrouter()
	auth.NewAuthentication(authentication, idp).Register(uar)
	api.NewClient(oauthManager).Register(ar)
	api.NewAuthorize(oauthManager).Register(ar)
	api.NewToken(oauthManager).Register(uar)
	api.NewJwks(jwks).Register(uar)
	ar.Use(authentication.Handler)

	log.Infof("Starting API server in port: %d", conf.API.Port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", conf.API.Port), cors.Handler(r)))
}
