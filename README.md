# ZMS PluggableAuthService Adapter


## SSO Plugin
Single-Sign-On

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

## License
Copyright (c) 2000-2023 SNTL Publishing <https://www.sntl-publishing.com>, Berlin. 
Code released under the _GNU General Public License v3 <http://www.gnu.org/licenses/gpl.html>_ license.
