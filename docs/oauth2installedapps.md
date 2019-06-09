# OAuth 2.0 for Mobile, Desktop and Single-page applications

This document explains how applications installed in mobile devices and computers can become [OAuth 2.0]
clients so they can obtain access to OAuth 2.0 Protected Resources owned by a user without
having to know the user credentials. It's the user (Resource Owner) who authorizes the application
to access to certain resources. This resources may include profile information, providing a centralized
*authentication* and *authorization* mechanism (see [OpenID Connect]). This flow also applies to
single-page applications (SPAs) which are run directly in the user's browser as if they were installed
in the device.

The common property of these kind of applications is that they are distributed to individual devices.
Therefore, the code of the application is inside the device and it cannot keep secrets, so it's not
safe for these applications to use a *client_secret*.

This [OAuth 2.0] flow is similar to the [Authorization Code](oauth2webserver.md), but adding an extension
known as [PKCE] (Proof Key for Code Exchange) so clients don't need to provide their *client_secret* to obtain
an access token. Installed apps have to open the system browser and supply a local redirect URI to handle the
response with the authorization code.

!!! info
    Mimir doesn't support the **Authorization Code** flow without client secret and without [PKCE]. One of them
    **MUST** be used.

## Obtaining OAuth 2.0 access tokens

The following steps show how applications installed in mobile devices and computers interact with **Mimir**
in order to obtain an *access token* to act on the user's behalf in front of a certain *Resource Server* protected with
[OAuth 2.0].

### Prerrequisite: Register the client in Mimir

In order to use this flow, the application must be registered as a client in **Mimir** to obtain
client credentials.

The client needs to declare that it wants to use the `authorization_code` flow.

The main concern for this kind of applications is the **redirect_uri** parameter.

- For Android, iOS and Universal Windows Platform (UWP) apps, your application can register a custom schema so
when the browser redirects to the application's `redirect_uri` the installed application code is invoked. For example:
`org.example.app://login`.
- Another option is to start a local web server listening on the loopback IP address (localhost), but it has the
caveat that the user has to be redirected somehow to the application (or instructed to do so from the browser).
- For single-page applications, the `redirect_uri` is just another HTTP URI handled by the application, so there isn't
any problem.

### Step 1: Generate a code verifier and challenge

According to the [PKCE] extension, in order to secure the authorization request in abscence of a client secret, before
the client begins with the authorization request it has to create a **code_verifier**.

A `code_verifier` is a high-entropy cryptographic random string using the characters
`[A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"`, with a minimum length of 43 characters and a maximum length of
128 characters. This code **MUST** be stored safely so it can be used later to obtain an access token.

Once the application has generated the `code_verifier`, the application needs to generate a **code_challenge** based
on the *code_verifier*. The `code_challenge` can be obtained using two methods:

Method | How to create
--- | ---
**S256** | The code challenge is the Base64 url-encoded SHA256 hash of the code verifier. `code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))`
**plain** | The code challenge is the same as the code verifier. This method should only be used if the application cannot perform a SHA256 hash. `code_challenge = code_verifier`

### Step 2: Obtain an authorization code

From your application, you have to redirect the user to **Mimir**'s authorization URL, setting the
query params properly to indicate the client identity and the grant flow desired. On native apps you'd need
to open a native browser or webview.

```http
GET https://[MIMIR_UI_URL]/oauth/authorize?
        response_type=code&
        client_id=[APPLICATION_CLIENT_ID]&
        redirect_uri=[APPLICATION_REDIRECT_URI]&
        scope=[REQUESTED_USER_ACCESS]&
        state=[APP_STATE]&
        code_challenge=[CODE_CHALLENGE]&
        code_challenge_method=[CODE_CHALLENGE_METHOD]
```

Parameter | Description | Required
--- | --- | ---
**response_type** | Indicates that the client expects to receive an authorization code. In this flow is always `code` | Yes
**client_id** | The client_id received when the application was registered. | Yes
**redirect_uri** | Indicates the URI to return the user to after authorization is complete. This URL of the application will receive the authorization code on user's authorization. It **MUST** match the one given during client registration. | Yes
**scope** | One or more space-delimited scope values indicating which parts of the user's account the client wish to access. If you want to obtain authentication info using [OpenID Connect] you should place the proper scopes here. | No
**state** | A client provided value which will be returned to the client in the callback endpoint, and can be used to store session information. | No
**code_challenge_method** | Specifies the method used to obtain the given code challenge. It can either be `plain` (the client has sent the code verifier) or `S256` (the client has sent a Base64 URL encoded SHA-256 hash of the code verifier) | Yes
**code_challenge** | Code challenge generated by the client so it can avoid sending the client_secret to request a token. The client generates a "code verifier" as a random string and then it sends this code verifier either as a Base64 URL encoded SHA-256 hash or as plain text. This code will be sent again in the token request to ensure that the request comes from the authorized client. | Yes

Example:

```http
GET https://accounts.example.org/oauth/authorize?
        response_type=code&
        client_id=1&
        redirect_uri=com.example.app:/oauth2redirect&
        scope=openid&
        state=a1b2c3&
        code_challenge_method=plain&
        code_challenge=1234
```

### Step 3: Obtain user's consent

**Mimir** shows a login form to the user, if he's not authenticated, so the user can provide his crendentials.

!!! note
    Usually in this step the user will be asked to grant explicit consent to the client to access the requested scopes.
    For the sake of simplicity, and assuming that only trusted users can register clients in the server right now, it's assumed
    that all the clients are first-party applications and therefore no confirmation form is shown.

This stage happens entirely in **Mimir**, so the client application doesn't need to do anything.

### Step 4: Receive authorization code in callback

Once the user has authorized the application, **Mimir** redirects the user back to the application's redirect URI,
adding the authorization code as a query parameter. How the client application receives the parameters
depends in what redirect URI scheme mechanism the application uses.

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

```HTTP
GET com.example.app:/oauth2redirect/login?
        code=e15sE.....egYl&
        state=a1b2c3
```

!!! note
    Usually in this step you'd also need to handle the error returned in case of a failure in the authorization request.
    Again, for the sake of simplicity errors are shown in **Mimir** and not passed to the client application.

### Step 5: Exchange authorization code for an access token

Once the user has granted consent to the client and the application has received an authorization code, the application
can exchange this code for an *access token* which can be used to access OAuth 2.0 Protected Resources.
Access token is obtained by making a POST request to the API exposed by **Mimir**, setting the proper form-encoded
parameters.

In this step, according to the [PKCE] extension, you have to provide the code verifier created in the [Step 1](#step-1-generate-a-code-verifier-and-challenge).

```http
POST https://[MIMIR_API]/v0/oauth/token
        grant_type=authorization_code&
        code=[RECEIVED_AUTH_CODE]&
        redirect_uri=[APPLICATION_REDIRECT_URI]&
        client_id=[APPLICAITON_CLIENT_ID]&
        code_verifier=[CODE_VERIFIER]
```

Parameter | Description | Required
--- | --- | ---
**grant_type** | The grant type for the Authentication Flow required. For this flow is always `authorization_code` | Yes
**code** | Authorization Code received in the previous step. | Yes
**redirect_uri** | Must be identical to the redirect URI used in the step 1. | Yes
**client_id** | Unique identifier of the client that requests the access token. | Yes
**code_verifier** | The plain code verifier created in the [Step 1](#step-1-generate-a-code-verifier-and-challenge) | Yes

Example:

```http
POST https://accounts.example.org/v0/oauth/token
        grant_type=authorization_code&
        code=e15sE.....egYl&
        redirect_uri=https://myapp.example.org/login&
        client_id=1&
        code_verifier=1234
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

### Step 6: Access Resource Servers

The application now can use the obtained access token to OAuth 2.0 Protected Resources. To do so, it just needs to
provide the token in the `Authorization` header:

`Authorization: Bearer [ACCESS_TOKEN]`

## Further information

If you still have doubts about how this flow works, you can obtain more (and better explained) info in the following links.

- <https://www.oauth.com/oauth2-servers/mobile-and-native-apps/>
- <https://www.oauth.com/oauth2-servers/single-page-apps/>
- <https://www.oauth.com/oauth2-servers/pkce/>
- <https://aaronparecki.com/oauth-2-simplified/#mobile-apps>
- <https://oauth.net/2/grant-types/authorization-code/>
- <https://oauth.net/2/native-apps/>
- <https://oauth.net/2/browser-based-apps/>
- <https://oauth.net/2/pkce/>
- <https://developers.google.com/identity/protocols/OAuth2InstalledApp>
- <https://tools.ietf.org/html/draft-ietf-oauth-native-apps-07>

[OAuth 2.0]: https://tools.ietf.org/html/rfc6749
[PKCE]: https://tools.ietf.org/html/rfc7636
[OpenID Connect]: openidconnect.md
