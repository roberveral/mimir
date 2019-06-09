# OAuth 2.0 for Native first-party applications

This document explains how a native first-party application can obtain access to OAuth 2.0 Protected Resources
owned by a user by exchanging the user's credentials for an
access token. This flow is against the primary design of [OAuth 2.0], which is to avoid that the
user has to introduce his credentials in the client application, but it comes in handy for native
applications of the same owner than **Mimir**. For instance, it's not surprising for a user to
enter his credentials in the Twitter Android app.

[Installed Applications] describes a more secure flow for a broader spectrum of use cases with these
kind of applications.

It's assumed that the clients which use this flow are not able to keep a secret (like [Installed Applications])
so no *client_secret* is required.

!!! warning
    This [OAuth 2.0] flow is called **Password** and it has a very concrete use case, so it must be used
    with caution and **NEVER** with third-party applications.

## Obtaining OAuth 2.0 access tokens

The following steps show how a native first-party application interacts with **Mimir** to obtain
an *access token* to act on the user's behalf in front of a certain *Resource Server* protected with
[OAuth 2.0].

### Prerrequisite: Register the client in Mimir

In order to use this flow, the application must be registered as a client in **Mimir** to obtain
client credentials.

The client needs to declare that it wants to use the `password` flow.

### Step 1: Obtain an access token

The client has to present a form to the user in order to retrieve the user's credentials. Once the user has
introduced its credentials, the client can exchange this credentials for an *access token* by making the
following POST request, sending the parameters form-encoded:

```http
POST https://[MIMIR_API]/v0/oauth/token
        grant_type=password&
        username=[USER_USERNAME]&
        password=[USER_PASSWORD]&
        client_id=[APPLICAITON_CLIENT_ID]&
        scope=[REQUESTED_USER_ACCESS]
```

Parameter | Description | Required
--- | --- | ---
**grant_type** | The grant type for the Authentication Flow required. For this flow is always `password` | Yes
**username** | User's username. | Yes
**password** | User's password. | Yes
**client_id** | Unique identifier of the client that requests the access token. | Yes
**scope** | One or more space-delimited scope values indicating which parts of the user's account the client wish to access. If you want to obtain authentication info using [OpenID Connect] you should place the proper scopes here. | No

Example:

```http
POST https://accounts.example.org/v0/oauth/token
        grant_type=password&
        username=jdoe&
        password=mysecretpassword&
        client_id=1&
        scope=openid
```

On a successful request, the server returns a 200 OK response with the following parameters in a JSON object.

Parameter | Description
--- | ---
**access_token** | Access token for the client and user, which can be used to request resources on user's behalf.
**token_type** | The type of token. In this flow is always `Bearer`.
**expires_in** | Time in seconds until token expiration.
**id_token** | A JWT token with the user's identity. Only sent if using [OpenID Connect] (`openid` scope).

Example:

```json
{
    "access_token": "c4GRb4....rTyB5",
    "token_type": "Bearer",
    "expires_in": 3600,
    "id_token": "e5GRf2....vYp39",
}
```

### Step 2: Access Resource Servers

The application now can use the obtained access token to OAuth 2.0 Protected Resources. To do so, it just needs to
provide the token in the `Authorization` header:

`Authorization: Bearer [ACCESS_TOKEN]`

## Further information

If you still have doubts about how this flow works, you can obtain more (and better explained) info in the following links.

- <https://www.oauth.com/oauth2-servers/access-tokens/password-grant/>
- <https://aaronparecki.com/oauth-2-simplified/>
- <https://oauth.net/2/grant-types/password/>

[OAuth 2.0]: https://tools.ietf.org/html/rfc6749
[Installed Applications]: oauth2installedapps.md
[OpenID Connect]: openidconnect.md
