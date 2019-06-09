# OAuth 2.0 Introduction

**Mimir** implements the [OAuth 2.0] protocol for authentication and authorization of the protected
resources. [OAuth 2.0] is an authorization framework that enables applications to obtain limited access
to user resources on an HTTP service. It works by delegating user authentication to an authorization server,
in this case **Mimir**, which hosts the user account, and authorizing third-party applications to access
the user resources.

[OAuth 2.0] provides authorization flows for web and desktop applications, and mobile devices.

In order to extend the [OAuth 2.0] framework to provide *authenticaton* in addition to *authorization*,
**Mimir** implements the [OpenID Connect] protocol to enable applications to obtain identity information
about the *end.user*.

## Concepts & Roles

In a [OAuth 2.0] flow there are different roles involved:

### User (Resource Owner)

The *user* is the person who authorizes a *client* to access certain parts of his account. It's also
known as **Resource Owner**. We're going to refer to him as *end-user*, also.

### Resource Server

The *Resource Server* is the HTTP API server which holds resources associated to a user account (owned by the user).
For now on, we're going to refer to this user resources as **OAuth 2.0 Protected Resources**.

### Client

The *client* is the applicaiton which is attempting to get access to certain *OAuth 2.0 Protected Resources* which
are part of the user's account. The client **MUST** be authorized by the user to do so.

Usually, a *client* is a third-party application, but it may be as well a first-party application,
when [OAuth 2.0] is used to provide Single-Sign On across all the organization applications.

### Authorization Server

The *authorization server* verifies the user identity (hosts the user account) and is in charge for asking
the user to authorize the client to access certain resources of his account.

In this case, **Mimir** is the authorization server.

## Supported flows

In the [OAuth 2.0] specification there are multiple authorization flows defined depending of the type of
*client* application.

**Mimir** supports the following flows:

Flow | Description | Recommended for
--- | --- | ---
[Authorization Code](oauth2webserver.md) | Most commonly used flow, optimized for server-side web applications and based in redirection and interaction with the browser. | Server-side web applications
[Authorization Code with PKCE](oauth2installedapps.md) | The `Authorization Code` flow but with an extension to avoid the need of a client secret. Optimized for installed applications. | Mobile apps (Android, iOS), Desktop apps, Single-Page Applications (SPAs)
[Password](oauth2nativefirstparty.md) | Requires the user to enter his credentials in the client application, so no redirection is required. Should only be used for native first-party apps. | Native first-party applications
[Client Credentials](oauth2serviceuser.md) | Allows the client to obtain a token to access his own resources. | Services accesing their own resources

## Further reading

- <https://www.digitalocean.com/community/tutorials/an-introduction-to-oauth-2>
- <https://aaronparecki.com/oauth-2-simplified/>

[OAuth 2.0]: https://tools.ietf.org/html/rfc6749
[OpenID Connect]: openidconnect.md
