# OpenID Connect

The [OAuth 2.0] framework is essentially an authorization framework, but it leaves room to include
authentication information. [OpenID Connect] adds an identity layer over [OAuth 2.0] so clients are
able to retrieve identity information about the end-user.

OAuth Server supports the use of a subset of the [OpenID Connect] specification to retrive identity
information.

## Authenticating the end-user

In order to use [OpenID Connect](https://openid.net/specs/openid-connect-core-1_0.html) to obtain identity
information of the end-user, you need to include some `scopes` in the OAuth authorization or token request
(depending on the flow). The following flows allow the use of OpenID Connect (only *three-legged flows*):

- [OAuth for Server-side web applications](oauth2webserver.md)
- [OAuth for Mobile, Desktop and Single-page applications](oauth2installedapps.md)
- [OAuth for Native first-party applications](oauth2nativefirstparty.md)

The different claims returned when requesting identity information depends on the scopes sent in the request.

The [scopes](https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims) supported by the OAuth Server
are the following:

Scope | Description | Required
--- | --- | ---
openid | Indicates that the user wants to obtain [OpenID Connect] information. | Yes
profile | This scope value requests access to the End-User's default profile claims. Includes `name` and `picture` claims. | No
email | This scope value requests access to the `email` claim. | No

Once the user has granted consent to the application to access the requested scopes, the client obtains in the
token request an access token which can be used to query identity information in the Userinfo endpoint and an 
**identity token** which contains all the requested identity information encoded in a JWT token.

### Identity token

The [Identity token](https://openid.net/specs/openid-connect-core-1_0.html#IDToken) is a JWT token signed by the OAuth Server
which contains identity information about the end-user authenticated in the OAuth flow.

An example payload of an *ID Token* requested with scope `openid profile email` is the following:

```json
{
  "aud": "f788bf4e-6a8d-49ba-821e-dc963afb4a29",
  "email": "jdoe@example.org",
  "exp": 1559857074,
  "iat": 1559846274,
  "iss": "http://localhost:8000",
  "name": "John Doe",
  "sub": "jdoe"
}
```

#### Validating the identity token

```json
{
    "keys": [
        {
            "use": "sig",
            "kty": "RSA",
            "kid": "1pOLkeY60s",
            "alg": "RS256",
            "n": "...",
            "e": "..."
        }
    ]
}
```

### Userinfo endpoint

```json
{
    "sub": "jdoe",
    "name": "John Doe",
    "email": "jdoe@example.org"
}
```

## Discovery document

```json
{
    "issuer": "http://localhost:8000",
    "authorization_endpoint": "http://localhost:8000/v0/oauth/authorize",
    "token_endpoint": "http://localhost:8000/v0/oauth/token",
    "userinfo_endpoint": "http://localhost:8000/v0/openid/userinfo",
    "jwks_uri": "http://localhost:8000/.well-known/jwks.json",
    "registration_endpoint": "http://localhost:8000/v0/clients",
    "scopes_supported": [
        "openid",
        "profile",
        "email"
    ],
    "response_types_supported": [
        "code"
    ],
    "grant_types_supported": [
        "authorization_code",
        "password",
        "client_credentials"
    ],
    "id_token_signing_alg_values_supported": [
        "RS256"
    ],
    "token_endpoint_auth_methods_supported": [
        "client_secret_post"
    ],
    "code_challenge_methods_supported": [
        "plain",
        "S256"
    ]
}
```

## Further reading

- <https://openid.net/connect/>
- <https://connect2id.com/learn/openid-connect>

[OAuth 2.0]: https://tools.ietf.org/html/rfc6749
[OpenID Connect]: https://openid.net/connect/
