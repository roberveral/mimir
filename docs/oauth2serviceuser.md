# OAuth for Service to Service communication

This document explains how [OAuth 2.0] can be used for service-to-service interactions. When a service
interacts with the Resource Servers protected by this OAuth Server, it uses an access token to act in
its own behalf. As the user is not involved in this flow, this kind of token is usually called *two-legged token*
(compared to the usual *three-legged token* when the user grants consent to the client to access his
resources).

This flow, called **Client Credentials**, can only be used to access the service's own data in the resource
servers or data which is not owned by any concrete user (or that its open to every registered user).

It's assumed than the clients that use this flow are backend services and therefore they can keep a secret.

## Obtaining OAuth 2.0 access tokens

The following steps show how a service interacts with the OAuth Server to obtain 
an access token to act on his own behalf in front of a certain Resource Server protected with 
[OAuth 2.0].

### Prerrequisite: Register the client in the OAuth Server

In order to use this flow, the application must be registered as a client in the OAuth Server to obtain
client credentials.

The client needs to declare that it wants to use the `client_credentials` flow.

### Step 1: Obtrain an access token

The client has to present a form to the user so it can obtain the user's credentials. Once the user has
introduced its credentials, the client can exchange this credentials for an access token by making the
following request with the parameters form-encoded:

```
POST https://[OAUTH_SERVER_API]/v0/oauth/token
    grant_type=client_credentials&
    client_id=[APPLICAITON_CLIENT_ID]&
    client_secret=[APPLICATION_CLIENT_SECRET]&
    scope=[REQUESTED_USER_ACCESS]
```

Parameter | Description | Required
--- | --- | ---
**grant_type** | The grant type for the Authentication Flow required. For this flow is always `client_credentials` | Yes
**client_id** | Unique identifier of the client that requests the access token. | Yes
**client_secret** | The client’s secret. This ensures the client's identity. | Yes
**scope** | One or more space-delimited scope values indicating which data the client wish to access. | No

Example:

```
POST https://accounts.example.org/v0/oauth/token
    grant_type=password&
    client_id=1&
    client_secret=1234&
    scope=openid
```

On a successful request, the server returns a 200 OK response with the following parameters in a JSON object.

Parameter | Description
--- | ---
**access_token** | Access token for the client and user, which can be used to request resources on user's behalf.
**token_type** | The type of token. In this flow is always `Bearer`.
**expires_in** | Time in seconds until token expiration.

Example:

```json
{
    "access_token": "c4GRb4....rTyB5",
    "token_type": "Bearer",
    "expires_in": 3600
}
```

### Step 2: Access Resource Servers

The application now can use the obtained access token to access APIs protected by OAuth. To do so, it just needs to
provide the token in the `Authorization` header:

`Authorization: Bearer [ACCESS_TOKEN]`

## Further information

If you still have doubts about how this flow works, you can obtain more (and better explained) info in the following links.

- <https://www.oauth.com/oauth2-servers/access-tokens/client-credentials/>
- <https://aaronparecki.com/oauth-2-simplified/>
- <https://oauth.net/2/grant-types/client-credentials/>

[OAuth 2.0]: https://tools.ietf.org/html/rfc6749
