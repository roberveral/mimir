package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"time"

	"github.com/roberveral/oauth-server/oauth"
	"github.com/roberveral/oauth-server/oauth/idp/ldap"
	"github.com/roberveral/oauth-server/oauth/repository/mongodb"
	"github.com/roberveral/oauth-server/oauth/token/jwt"
	"github.com/roberveral/oauth-server/utils"

	"github.com/gorilla/mux"
	"github.com/roberveral/oauth-server/api"
	"github.com/roberveral/oauth-server/api/auth"
	"github.com/rs/cors"
	log "github.com/sirupsen/logrus"
)

const apiVersion = "/v0"

func main() {
	log.SetLevel(log.DebugLevel)

	log.Info("OAuth Authorization Server - Starting...")

	port := 8000
	oauthStore, err := mongodb.New("mongodb://localhost:27017", "oauth")
	if err != nil {
		log.Fatal(err)
		return
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatal("Unable to load LDAP IDP from configuration: ", err)
		return
	}
	oauthProvider, err := jwt.New(privateKey)
	if err != nil {
		log.Fatal("Unable to load OAuth Manager from configuration: ", err)
		return
	}
	idp, err := ldap.New("ldap://localhost", "cn=readonly,dc=example,dc=org", "readonly",
		ldap.WithBaseDN("dc=example,dc=org"),
		ldap.WithNameAttr("gecos"))
	if err != nil {
		log.Fatal("Unable to load JWT from configuration: ", err)
		return
	}

	oauthManager := oauth.NewManager(idp, oauthStore, oauthProvider)

	corsMw := cors.New(cors.Options{
		AllowedHeaders: []string{"*"},
	})

	signKey := utils.RandString(20)
	authJwt, err := auth.NewJwt(3*time.Hour, signKey, "oauth-server")
	if err != nil {
		log.Fatal(err)
		return
	}

	jwks, err := oauthProvider.GetJwks()
	if err != nil {
		log.Fatal(err)
		return
	}

	// Instantiate HTTP request router
	r := mux.NewRouter()
	ar := r.PathPrefix(apiVersion).Subrouter()
	uar := r.PathPrefix(apiVersion).Subrouter()
	auth.NewAuthentication(authJwt, idp).Register(uar)
	api.NewClient(oauthManager).Register(ar)
	api.NewAuthorize(oauthManager).Register(ar)
	api.NewToken(oauthManager).Register(uar)
	api.NewJwks(jwks).Register(uar)
	ar.Use(authJwt.Handler)

	log.Infof("Starting server in port %d", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), corsMw.Handler(r)))
}
