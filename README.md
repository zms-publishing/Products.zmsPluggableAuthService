# ZMS PluggableAuthService Adapter
The ZMS adapter for [Zope's Pluggable Authentication Service, PAS](https://github.com/zopefoundation/Products.PluggableAuthService) delivers four adapters each providing specific API functions of the  PAS authentication process:
1. *ZMS PAS Cookie Auth Helper*: containing a login form and the auth cookie name
2. *ZMS PAS Role Plugin*: containing the API methods authenticateCredentialsImpl and enumerateUsersImpl for connection external user repositories
3. *ZMS PAS User Plugin*: containing the API method getRolesForPrincipalImpl
3. *ZMS PAS SSO Plugin*: processing an [OpenID-Connect (OIDC)](https://en.wikipedia.org/wiki/OpenID#OpenID_Connect_(OIDC)) conformant http header for several authentication steps (credential extraction, authentication etc.)


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
*Optional\*:* Roles&nbsp;Name&nbsp;Attribute | `roles_attr` | the name of the http header payload field representing a list of roles. 

 \* *The ZMS PluggableAuthService SSO Plugin is able to extract the user roles; for this an attribute "roles_attr" (string type) must be added manually to the perperty list*

## License
Copyright (c) 2000-2023 SNTL Publishing <https://www.sntl-publishing.com>, Berlin. 
Code released under the _GNU General Public License v3 <http://www.gnu.org/licenses/gpl.html>_ license.
