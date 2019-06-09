# Mimir

**Mimir** is an OAuth 2.0 and OpenID Connect compilant Authorization Server implementation in Golang.

Mimir uses LDAP as *Identity Provider*, so user accounts are fetched from the configured LDAP directory.
This allows **Mimir** to integrate with multiple organizations, providing an OAuth 2.0 server.
