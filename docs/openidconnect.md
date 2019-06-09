# OpenID Connect

The [OAuth 2.0] framework is essentially an authorization framework, but it leaves room to build an
authentication mechanism on top of it. [OpenID Connect] adds an identity layer over [OAuth 2.0] so
clients are able to retrieve identity information about the end-user who has granted consent to the
client to act on his behalf.

**Mimir** supports a subset of the [OpenID Connect] specification to retrieve identity information.

## Authenticating the end-user

In order to use [OpenID Connect](https://openid.net/specs/openid-connect-core-1_0.html) to obtain identity
information of the end-user, you need to include certain `scopes` in the OAuth authorization or token request
(depending on the flow). Only the flows involving an end-user (*three-legged*) allow the use of OpenID Connect.

- [OAuth for Server-side web applications](oauth2webserver.md)
- [OAuth for Mobile, Desktop and Single-page applications](oauth2installedapps.md)
- [OAuth for Native first-party applications](oauth2nativefirstparty.md)

The different [claims](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims), which are identity
information about the end-user, returned when requesting identity information depend on the scopes sent in the
request and granted by the user.

The [scopes](https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims) supported by **Mimir**
are the following:

Scope | Description | Required
--- | --- | ---
**openid** | Indicates that the user wants to obtain [OpenID Connect] information. | Yes
**profile** | This scope value requests access to the End-User's default profile claims. Includes `name` and `picture` claims. | No
**email** | This scope value requests access to the `email` claim. | No

Once the user has granted consent to the application to access the requested scopes, the client obtains in the
token request an access token which can be used to query identity information in the **UserInfo endpoint** and an
**identity token** which contains all the requested identity information encoded in a [JWT] token.

### Identity token

The [Identity token](https://openid.net/specs/openid-connect-core-1_0.html#IDToken) is a [JWT] token digitally
signed by **Mimir** which contains identity information about the end-user authenticated in the OAuth flow.

An example payload of an *Identity Token* requested with scopes `openid profile email` is the following:

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

The identity token can be decoded and validated by clients to obtain the identity information trusting that
the token contents are valid.

#### Validating the identity token

Identity tokens can be used to pass identity information from the client applications to backend services.
Those services that don't obtain identity information directly from Mimir **MUST** validate the identity
token to ensure that it's still valid.

!!! warning
    In order to keep the token safe, services which receive [JWT] tokens **MUST** use HTTPS.

As the identity token is a signed [JWT] token, there're two main validations required:

- **Validate the signature**: token's signature must be validated in order to guarantee that the token contents
have not been manipulated since the token creation in **Mimir**.
- **Check token expiration**: expired tokens must never be accepted. Expiration time is sent in the `exp` claim.

In order to validate the token's signature, the key used by the server to sign the token is needed. **Mimir** supports
[JWK] (JSON Web Keys) so it exposes its public key in the API so clients can validate the signature.

```http
GET https://[MIMIR_API]/.well-known/jwks.json
```

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

!!! tip
    To play with [JWT] validation, check out [jwt.io](https://jwt.io/), which allows you to validate a token
    (and it automatically fetches the public key based on the issuer using [JWK]).

### UserInfo endpoint

The [UserInfo Endpoint](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo) is an OAuth 2.0 Protected
Resource that returns claims about the authenticated End-User. In order to use this endpoint clients need to
provide an *access token* which has the [OpenID Connect] scopes granted.

```http
GET https://[MIMIR_API]/v0/openid/userinfo
Authorization: Bearer [ACCESS_TOKEN]
```

```json
{
    "sub": "jdoe",
    "name": "John Doe",
    "email": "jdoe@example.org"
}
```

The information obtained is the same as the one contained in the *identity token*, therefore extracting the information
from the *identity token* is preferred as it avoids one network call.

## Discovery document

The [OpenID Connect] protocol requires the use of multiple endpoints for authenticating users, and for requesting resources
including tokens, user information, and public keys.

To simplify implementations and increase flexibility, [OpenID Connect] allows the use of a [Discovery document](https://openid.net/specs/openid-connect-discovery-1_0.html), a
JSON document found at a well-known location containing key-value pairs which provide details about the [OpenID Connect]
provider's configuration, including the URIs of the authorization, token, userinfo, and public-keys endpoints.

**Mimir**'s discovery document can be obtained in the following URL.

```http
GET https://[MIMIR_API]/.well-known/openid-configuration
```

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
- <https://www.oauth.com/oauth2-servers/openid-connect/>

[OAuth 2.0]: https://tools.ietf.org/html/rfc6749
[OpenID Connect]: https://openid.net/connect/
[JWT]: https://tools.ietf.org/html/rfc7519
[JWK]: https://tools.ietf.org/html/rfc7517
