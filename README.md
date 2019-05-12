# oauth-server
An OAuth Authorization server written in Go

## Getting started

1. Start necessary Docker Containers

```bash
docker run --name oauth-mongo -d -p 27017:27017 mongo
docker run --name oauth-ldap -d -p 389:389 -p 636:636 -e LDAP_READONLY_USER=true osixia/openldap:1.2.4
```

2. Launch Oauth Authorizaton Server

```bash
export APP_API_PORT=8000
export APP_API_JWT_KEY=F4QJ9VQWr65U27C8A84v
export APP_LDAP_URL=ldap://localhost
export APP_LDAP_USER_DN="cn=readonly,dc=example,dc=org"
export APP_LDAP_PASSWORD=readonly
export APP_LDAP_BASE_DN="dc=example,dc=org"
export APP_LDAP_NAME_ATTR=gecos
export APP_MONGO_URL=mongodb://localhost:27017
export APP_MONGO_DB=oauth

go run main.go
```

3. Add users to LDAP to allow authentication

```bash
docker exec -ti oauth-ldap ldapadd -x -D "cn=admin,dc=example,dc=org" -w admin -H ldap://localhost -ZZ

dn: uid=jdoe,dc=example,dc=org
uid: jdoe
cn: jdoe
sn: 3
objectClass: top
objectClass: posixAccount
objectClass: inetOrgPerson
loginShell: /bin/bash
homeDirectory: /home/jdoe
uidNumber: 14583102
gidNumber: 14564100
userPassword: jdoe
mail: jdoe@example.org
gecos: John Doe

```
