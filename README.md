# ZMS PluggableAuthService Adapter
#
## SSO Plugin
Single-Sign-On

### Prerequisites
* ``itsdangerous``: Various helpers to pass data to untrusted environments and to get it back safe and sound. Data is cryptographically signed to ensure that a token has not been tampered with.
   https://pypi.org/project/itsdangerous/

### Properties
Name | Value | Description
--- | --- | ---
Header Name | HTTP_X_AUTH_RESULT | the name of the HTTP-header containing the OIDC auth-result
Secret Key |  | the secret key used to decrypt the auth-result using the itsdangerous-module
Login Path | http://zms.hosting/auth/login | the path for redirection from challenge to SSO login.
Login Pattern | https?:\/\/(edit\.|www.cmstest)(.*) | the pattern of original url for redirection from challenge to SSO login.
Came From | came_from | the name of the request-parameter containing the original url the request came from

## License
Copyright (c) 2000-2022 `SNTL Publishing <http://www.sntl-publishing.com>`_, Berlin. 
Code released under the `GNU General Public License v3 <http://www.gnu.org/licenses/gpl.html>`_ license.
