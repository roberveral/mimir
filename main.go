package main

import (
	"github.com/roberveral/mimir/config"

	"github.com/gorilla/mux"
	"github.com/roberveral/mimir/api"
	"github.com/roberveral/mimir/api/auth"
	log "github.com/sirupsen/logrus"
)

const apiVersion = "/v0"

func main() {
	log.Info("Mimir - Starting...")

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
	jwtEncoder, err := conf.JWT.Encoder()
	if err != nil {
		log.Fatal("Unable to create JWT encoder: ", err)
		return
	}
	idp, err := conf.Ldap.IdentityProvider()
	if err != nil {
		log.Fatal("Unable to create LDAP connector: ", err)
		return
	}

	oauthManager := conf.OAuth.Manager(idp, store, jwtEncoder)

	authentication, err := conf.API.Authentication()
	if err != nil {
		log.Fatal("Unable to configure API authentication: ", err)
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
	api.NewOpenID(oauthManager).Register(uar)
	api.NewDiscovery(oauthManager).Register(r)
	ar.Use(authentication.Handler)

	log.Fatal(conf.API.Start(r, conf.Debug))
}
