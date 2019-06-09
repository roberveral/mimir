# OAuth 2.0 for Server-side web applications

This document explains how a server-side web application can become an [OAuth 2.0] client so
it can obtain access to OAuth 2.0 Protected Resources owned by a user without
having to know the user credentials. It's the user (Resource Owner) who authorizes the application
to access to certain resources. This resources may include profile information, providing a centralized
*authentication* and *authorization* mechanism (see [OpenID Connect]).

This [OAuth 2.0] flow is called **Authorization Code**, and it's designed to work with applications
which can keep confidential information. Therefore it should only be used with backend servers.

!!! warning
    This flow **MUST NOT** be implemented in a client-side Single-Page Application (SPA) like Angular. Check [OAuth for Mobile, Desktop and Single-page applications](oauth2installedapps.md) instead.
    If the application has such a frontend, this flow should only be implemented through a backend API.

## Obtaining OAuth 2.0 access tokens

The following steps show how a server-side web application interacts with **Mimir** to obtain
an *access token* to act on the user's behalf in front of a certain *Resource Server* protected with
[OAuth 2.0].

### Prerrequisite: Register the client in Mimir

In order to use this flow, the application must be registered as a client in **Mimir** to obtain
client credentials.

The client needs to declare that it wants to use the `authorization_code` flow.

### Step 1: Obtain an authorization code

From your application, you have to redirect the user to **Mimir**'s authorization URL, setting the
query params properly to indicate the client identity and the grant flow desired.

```http
GET https://[MIMIR_UI_URL]/oauth/authorize?
        response_type=code&
        client_id=[APPLICATION_CLIENT_ID]&
        redirect_uri=[APPLICATION_REDIRECT_URI]&
        scope=[REQUESTED_USER_ACCESS]&
        state=[APP_STATE]
```

Parameter | Description | Required
--- | --- | ---
**response_type** | Indicates that the client expects to receive an authorization code. In this flow is always `code` | Yes
**client_id** | The client_id received when the application was registered. | Yes
**redirect_uri** | Indicates the URI to return the user to after authorization is complete. This URL of the application will receive the authorization code on user's authorization. It **MUST** match the one given during client registration. | Yes
**scope** | One or more space-delimited scope values indicating which parts of the user's account the client wish to access. If you want to obtain authentication info using [OpenID Connect] you should place the proper scopes here. | No
**state** | A client provided value which will be returned to the client in the callback endpoint, and can be used to store session information. | No

Example:

```http
GET https://accounts.example.org/oauth/authorize?
        response_type=code&
        client_id=1&
        redirect_uri=https://myapp.example.org/login&
        scope=openid&
        state=a1b2c3
```

### Step 2: Obtain user's consent

**Mimir** shows a login form to the user, if he's not authenticated, so the user can provide his crendentials.

!!! note
    Usually in this step the user will be asked to grant explicit consent to the client to access the requested scopes.
    For the sake of simplicity, and assuming that only trusted users can register clients in the server right now, it's assumed
    that all the clients are first-party applications and therefore no confirmation form is shown.

This stage happens entirely in **Mimir**, so the client application doesn't need to do anything.

### Step 3: Receive authorization code in callback

Once the user has authorized the application, **Mimir** redirects the user back to the application's redirect URI,
adding the authorization code as a query parameter.

```http
GET [REDIRECT_URI]?
        code=[AUTHORIZATION_CODE]&
        state=[APPLICATION_STATE]
```

Parameter | Description
--- | ---
**code** | The authorization code returned by the server.
**state** | The same state value passed in the authorization request, if any.

Example:

```http
GET https://myapp.example.org/login?
        code=e15sE.....egYl&
        state=a1b2c3
```

!!! note
    Usually in this step you'd also need to handle the error returned in case of a failure in the authorization request.
    Again, for the sake of simplicity errors are shown in **Mimir** and not passed to the client application.

### Step 4: Exchange authorization code for an access token

Once the user has granted consent to the client and the application has received an authorization code, the server
backend can exchange this code for an access token which can be used to access OAuth 2.0 Protected Resources.
Access token is obtained by making a POST request to the API exposed by **Mimir**, setting the proper form-encoded
parameters.

```http
POST https://[MIMIR_API]/v0/oauth/token
        grant_type=authorization_code&
        code=[RECEIVED_AUTH_CODE]&
        redirect_uri=[APPLICATION_REDIRECT_URI]&
        client_id=[APPLICAITON_CLIENT_ID]&
        client_secret=[APPLICATION_CLIENT_SECRET]
```

Parameter | Description | Required
--- | --- | ---
**grant_type** | The grant type for the Authentication Flow required. For this flow is always `authorization_code` | Yes
**code** | Authorization Code received in the previous step. | Yes
**redirect_uri** | Must be identical to the redirect URI used in the step 1. | Yes
**client_id** | Unique identifier of the client that requests the access token. | Yes
**client_secret** | The client’s secret. This ensures the client's identity. | Yes

Example:

```http
POST https://accounts.example.org/v0/oauth/token
        grant_type=authorization_code&
        code=e15sE.....egYl&
        redirect_uri=https://myapp.example.org/login&
        client_id=1&
        client_secret=secret
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
    "expires_in": 3600
}
```

### Step 5: Access Resource Servers

The application now can use the obtained access token to OAuth 2.0 Protected Resources. To do so, it just needs to
provide the token in the `Authorization` header:

`Authorization: Bearer [ACCESS_TOKEN]`

## Further information

If you still have doubts about how this flow works, you can obtain more (and better explained) info in the following links.

- <https://www.oauth.com/oauth2-servers/server-side-apps/>
- <https://aaronparecki.com/oauth-2-simplified/>
- <https://oauth.net/2/grant-types/authorization-code/>

[OAuth 2.0]: https://tools.ietf.org/html/rfc6749
[OpenID Connect]: openidconnect.md
