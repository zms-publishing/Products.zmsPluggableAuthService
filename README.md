# ZMS PluggableAuthService Adapter
The ZMS adapter for [Zope's Pluggable Authentication Service, PAS](https://github.com/zopefoundation/Products.PluggableAuthService) delivers adapters providing specific API functions of the PAS authentication process:
1. *ZMS PAS Cookie Auth Helper*: containing a login form and the auth cookie name
2. *ZMS PAS Role Plugin*: containing the API methods authenticateCredentialsImpl and enumerateUsersImpl for connection external user repositories
3. *ZMS PAS User Plugin*: containing the API method getRolesForPrincipalImpl
3. *ZMS PAS SSO Plugin*: processing an [OpenID-Connect (OIDC)](https://en.wikipedia.org/wiki/OpenID#OpenID_Connect_(OIDC)) conformant http header for several authentication steps (credential extraction, authentication etc.)
4. *ZMS PAS WebAuthn Plugin*: passkey registration and authentication for existing PAS users.


## SSO Plugin: Using OIDC conformant Single-Sign-On

### Prerequisites
* *itsdangerous*: Various helpers to pass data to untrusted environments and to get it back safe and sound. Data is cryptographically signed to ensure that a token has not been tampered with.
   https://pypi.org/project/itsdangerous/

### Zope Object's Properties
Name | Value | Description
--- | --- | ---
Header&nbsp;Name | `HTTP_X_AUTH_RESULT` | the name of the HTTP-header containing the OIDC auth-result
Secret&nbsp;Key | `******************` | the secret key used to decrypt the auth-result using the _itsdangerous_-module
Login&nbsp;Path | `http://zms.hosting/auth/login` | the path for redirection from challenge to SSO login.
Login&nbsp;Pattern | `https?:\/\/(.*)\/manage` | the pattern of original url for redirection from challenge to SSO login.
Came&nbsp;From | `came_from` | the name of the request-parameter containing the original url the request came from
User&nbsp;ID Attributes | `user_id,sub` | the name(s) of the http header payload fields representing the user id.
Do Add&nbsp;User on OIDC Key:Value | `doAddUser_on_oidc_key` | Successful OIDC authentication implies user-data capturing (\_users-property) if the given _key:value_ pair (separator is colon) is found on OIDC payload. If `doAddUser_on_oidc_key` is an empty value (default) the data capturing will not happen.
*Optional\*:* `roles_attr` | `roles_attr` | the name of the http header payload field representing a list of roles. 

 \* *The ZMS PluggableAuthService SSO Plugin is able to extract the user roles; for this a new attribute named "roles_attr" (string type) must be added manually to the property list*

## WebAuthn Plugin

Install the optional `webauthn` extra (`Products.zmsPluggableAuthService[webauthn]`)
in the Zope environment and restart Zope. Add a **ZMS PluggableAuthService
WebAuthn Plugin** inside the relevant `acl_users`. Configure the RP ID as the
site's domain (for example `example.com`) and the exact externally visible HTTPS
origin (for example `https://example.com`, including any non-default port).
The origin host must equal the RP ID or be its subdomain. HTTPS must reach the
browser, including when Zope runs behind a TLS-terminating reverse proxy.

Activate the plugin's **Extraction**, **Authentication**, and **Credentials
Reset** interfaces in PAS. An active user enumeration plugin is also required.
Open the plugin's `login_form` to register, sign in, or remove all passkeys.
Registration requires an existing user already authenticated by this same PAS;
login uses the PAS **user ID**, which may differ from the login name. The form
is a page template created with the plugin and can be customized.

Credentials, one-use challenges and hashed session tokens are stored in the
ZODB. WebAuthn user verification is required. Login uses an HttpOnly, Secure,
SameSite=Strict cookie valid for 12 hours; PAS logout revokes that session.
Removing passkeys also revokes all passkey sessions for that user. Remove a
user's passkeys before deleting or reusing their PAS user ID; deletion by an
external user directory does not automatically remove stored passkeys. Limit
access to the plugin's login endpoints at the reverse proxy if rate limiting is
required.

## License
Copyright (c) 2000-2026 SNTL Publishing <https://www.sntl-publishing.com>, Berlin. 
Code released under the _GNU General Public License v3 <http://www.gnu.org/licenses/gpl.html>_ license.
