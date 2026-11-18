"""WebAuthn authentication for existing PAS users."""

import hashlib
import json
import logging
import secrets
import time
from pathlib import Path
from urllib.parse import urlsplit

from AccessControl.SecurityInfo import ClassSecurityInfo
from AccessControl.class_init import InitializeClass
from Acquisition import aq_base, aq_parent
from OFS.Folder import Folder
from persistent.mapping import PersistentMapping
from Products.PageTemplates.PageTemplateFile import PageTemplateFile
from Products.PageTemplates.ZopePageTemplate import ZopePageTemplate
from Products.PluggableAuthService.interfaces.plugins import IAuthenticationPlugin
from Products.PluggableAuthService.interfaces.plugins import ICredentialsResetPlugin
from Products.PluggableAuthService.interfaces.plugins import IExtractionPlugin
from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from Products.PluggableAuthService.utils import classImplements
from zope.interface import Interface


logger = logging.getLogger("ZMSPASWebauthn")
CHALLENGE_LIFETIME = 120
SESSION_LIFETIME = 12 * 60 * 60
MAX_CHALLENGES = 1000


class IZMSPASWebauthn(Interface):
    """Marker interface."""


manage_addZMSPASWebauthnForm = PageTemplateFile(
    "www/zpwebauthnAdd", globals(), __name__="manage_addZMSPASWebauthnForm"
)


def addZMSPASWebauthn(dispatcher, id, title="", rp_id="", origin="", REQUEST=None):
    """Add a WebAuthn plugin to PAS."""
    plugin = ZMSPASWebauthn(id, title, rp_id, origin)
    dispatcher._setObject(id, plugin)
    if REQUEST is not None:
        REQUEST.RESPONSE.redirect(
            "%s/manage_workspace?manage_tabs_message=WebAuthn+plugin+added."
            % dispatcher.absolute_url()
        )


class ZMSPASWebauthn(Folder, BasePlugin):
    """Register and authenticate passkeys belonging to existing PAS users."""

    meta_type = "ZMS PluggableAuthService WebAuthn Plugin"
    zmi_icon = "fas fa-key"
    zmi_show_add_dialog = True
    security = ClassSecurityInfo()
    manage_options = (
        BasePlugin.manage_options[:1] + Folder.manage_options[:1]
        + Folder.manage_options[2:]
    )
    _properties = (
        {"id": "title", "label": "Title", "type": "string", "mode": "w"},
        {"id": "rp_id", "label": "RP ID", "type": "string", "mode": "w"},
        {"id": "origin", "label": "Origin", "type": "string", "mode": "w"},
        {"id": "rp_name", "label": "RP Name", "type": "string", "mode": "w"},
    )

    def __init__(self, id, title="", rp_id="", origin=""):
        self._setId(id)
        self.title = title
        self.rp_id = rp_id
        self.origin = origin
        self.rp_name = title or "ZMS"
        self._credentials = PersistentMapping()
        self._user_handles = PersistentMapping()
        self._challenges = PersistentMapping()
        self._sessions = PersistentMapping()
        self._validate_configuration()

    security.declarePrivate("manage_afterAdd")
    def manage_afterAdd(self, item, container):
        if "login_form" not in self.objectIds():
            text = (Path(__file__).parent / "www" / "webauthn_login.zpt").read_text(
                encoding="utf-8"
            )
            page = ZopePageTemplate("login_form", text=text)
            page.title = "WebAuthn login"
            page.manage_permission("View", roles=["Anonymous"], acquire=0)
            self._setObject("login_form", page, set_owner=0)

    def _validate_configuration(self):
        parsed = urlsplit(self.origin)
        hostname = parsed.hostname
        if (
            parsed.scheme != "https" or not hostname or parsed.username
            or parsed.password or parsed.path or parsed.query or parsed.fragment
            or self.origin != "https://" + parsed.netloc
            or not self.rp_id or self.rp_id != self.rp_id.lower()
            or (hostname != self.rp_id and not hostname.endswith("." + self.rp_id))
        ):
            raise ValueError("Configure an HTTPS origin and a matching RP ID.")
        try:
            parsed.port
        except ValueError as exc:
            raise ValueError("Invalid origin port.") from exc

    def _cookie_name(self, kind):
        name = "/".join(self.getPhysicalPath()) + ":" + kind
        return "__Host-zmswebauthn-" + hashlib.sha256(name.encode()).hexdigest()[:24]

    def _set_cookie(self, response, kind, value, max_age):
        response.setCookie(
            self._cookie_name(kind), value, path="/", secure=True, httponly=True,
            samesite="Strict", max_age=max_age,
        )

    def _expire_cookie(self, response, kind):
        response.expireCookie(
            self._cookie_name(kind), path="/", secure=True, httponly=True,
            samesite="Strict",
        )

    @staticmethod
    def _token_key(token):
        return hashlib.sha256(token.encode("ascii")).hexdigest()

    def _request_data(self, request):
        self._validate_configuration()
        if request.get("REQUEST_METHOD") != "POST":
            raise ValueError("POST required.")
        if request.get("HTTP_ORIGIN") != self.origin:
            raise ValueError("Invalid request origin.")
        if request.get("CONTENT_TYPE", "").split(";", 1)[0].strip().lower() != "application/json":
            raise ValueError("JSON content type required.")
        body = request.get("BODY", b"")
        if len(body) > 65536:
            raise ValueError("Request body is too large.")
        data = json.loads(body)
        if not isinstance(data, dict):
            raise ValueError("A JSON object is required.")
        return data

    def _respond(self, request, data, status=200):
        response = request.RESPONSE
        response.setStatus(status)
        response.setHeader("Content-Type", "application/json")
        response.setHeader("Cache-Control", "no-store")
        return json.dumps(data)

    def _current_user(self, request):
        user = request.get("AUTHENTICATED_USER")
        pas = aq_parent(self)
        if user is None or aq_base(aq_parent(user)) is not aq_base(pas):
            raise ValueError("Sign in to this PAS before registering a passkey.")
        user_id = user.getId()
        if not user_id or pas.getUserById(user_id) is None:
            raise ValueError("An existing PAS user is required.")
        return user_id

    def _new_challenge(self, request, operation, user_id, challenge):
        now = time.time()
        for key, entry in list(self._challenges.items()):
            if entry["expires"] <= now:
                del self._challenges[key]
        if len(self._challenges) >= MAX_CHALLENGES:
            raise ValueError("Too many pending passkey operations. Try again later.")
        token = secrets.token_urlsafe(32)
        self._challenges[self._token_key(token)] = {
            "operation": operation, "user_id": user_id, "challenge": challenge,
            "expires": now + CHALLENGE_LIFETIME,
        }
        self._set_cookie(request.RESPONSE, "challenge", token, CHALLENGE_LIFETIME)

    def _take_challenge(self, request, operation):
        token = request.cookies.get(self._cookie_name("challenge"), "")
        self._expire_cookie(request.RESPONSE, "challenge")
        try:
            key = self._token_key(token)
        except (UnicodeEncodeError, AttributeError):
            raise ValueError("Invalid challenge.") from None
        entry = self._challenges.pop(key, None)
        if not entry or entry["operation"] != operation or entry["expires"] <= time.time():
            raise ValueError("Challenge is missing or expired.")
        return entry

    security.declarePublic("registration_options")
    def registration_options(self, REQUEST):
        """Begin enrollment for the currently authenticated PAS user."""
        try:
            self._request_data(REQUEST)
            user_id = self._current_user(REQUEST)
            from webauthn import generate_registration_options, options_to_json
            from webauthn.helpers.structs import (
                AuthenticatorSelectionCriteria, PublicKeyCredentialDescriptor,
                UserVerificationRequirement,
            )
            handle = self._user_handles.get(user_id)
            if handle is None:
                handle = secrets.token_bytes(32)
                self._user_handles[user_id] = handle
            existing = [
                PublicKeyCredentialDescriptor(id=key)
                for key, value in self._credentials.items() if value["user_id"] == user_id
            ]
            options = generate_registration_options(
                rp_id=self.rp_id, rp_name=self.rp_name, user_id=handle,
                user_name=user_id, exclude_credentials=existing,
                authenticator_selection=AuthenticatorSelectionCriteria(
                    user_verification=UserVerificationRequirement.REQUIRED
                ),
            )
            self._new_challenge(REQUEST, "registration", user_id, options.challenge)
            return self._respond(REQUEST, json.loads(options_to_json(options)))
        except (ValueError, UnicodeError) as exc:
            return self._respond(REQUEST, {"error": str(exc)}, 400)

    security.declarePublic("registration_finish")
    def registration_finish(self, REQUEST):
        """Verify and store an enrolled public key."""
        from webauthn import verify_registration_response
        from webauthn.helpers.exceptions import WebAuthnException
        try:
            data = self._request_data(REQUEST)
            entry = self._take_challenge(REQUEST, "registration")
            if self._current_user(REQUEST) != entry["user_id"]:
                raise ValueError("The authenticated user changed during registration.")
            result = verify_registration_response(
                credential=data, expected_challenge=entry["challenge"],
                expected_rp_id=self.rp_id, expected_origin=self.origin,
                require_user_verification=True,
            )
            if result.credential_id in self._credentials:
                raise ValueError("This passkey is already registered.")
            self._credentials[result.credential_id] = {
                "user_id": entry["user_id"], "public_key": result.credential_public_key,
                "sign_count": result.sign_count,
            }
            return self._respond(REQUEST, {"ok": True})
        except (ValueError, UnicodeError, TypeError, WebAuthnException) as exc:
            logger.info("WebAuthn registration failed: %s", exc)
            return self._respond(REQUEST, {"error": "Passkey registration failed."}, 400)

    security.declarePublic("authentication_options")
    def authentication_options(self, REQUEST):
        """Begin a passkey login for a PAS user ID."""
        try:
            data = self._request_data(REQUEST)
            user_id = data.get("user_id")
            if not isinstance(user_id, str) or not user_id or len(user_id) > 256:
                raise ValueError("A valid user ID is required.")
            from webauthn import generate_authentication_options, options_to_json
            from webauthn.helpers.structs import PublicKeyCredentialDescriptor, UserVerificationRequirement
            allowed = [
                PublicKeyCredentialDescriptor(id=key)
                for key, value in self._credentials.items() if value["user_id"] == user_id
            ]
            if not allowed or aq_parent(self).getUserById(user_id) is None:
                raise ValueError("No passkey is available for this user.")
            options = generate_authentication_options(
                rp_id=self.rp_id, allow_credentials=allowed,
                user_verification=UserVerificationRequirement.REQUIRED,
            )
            self._new_challenge(REQUEST, "authentication", user_id, options.challenge)
            return self._respond(REQUEST, json.loads(options_to_json(options)))
        except (ValueError, UnicodeError) as exc:
            return self._respond(REQUEST, {"error": str(exc)}, 400)

    security.declarePublic("authentication_finish")
    def authentication_finish(self, REQUEST):
        """Verify the assertion and issue a revocable login cookie."""
        from webauthn import base64url_to_bytes, verify_authentication_response
        from webauthn.helpers.exceptions import WebAuthnException
        try:
            data = self._request_data(REQUEST)
            entry = self._take_challenge(REQUEST, "authentication")
            credential_id = base64url_to_bytes(data["id"])
            credential = self._credentials.get(credential_id)
            if credential is None or credential["user_id"] != entry["user_id"]:
                raise ValueError("Unknown credential.")
            pas_user = aq_parent(self).getUserById(entry["user_id"])
            if pas_user is None:
                raise ValueError("User no longer exists.")
            result = verify_authentication_response(
                credential=data, expected_challenge=entry["challenge"],
                expected_rp_id=self.rp_id, expected_origin=self.origin,
                credential_public_key=credential["public_key"],
                credential_current_sign_count=credential["sign_count"],
                require_user_verification=True,
            )
            self._credentials[credential_id] = dict(
                credential, sign_count=result.new_sign_count
            )
            now = time.time()
            for key, session in list(self._sessions.items()):
                if session["expires"] <= now:
                    del self._sessions[key]
            token = secrets.token_urlsafe(32)
            self._sessions[self._token_key(token)] = {
                "user_id": entry["user_id"], "expires": now + SESSION_LIFETIME,
            }
            self._set_cookie(REQUEST.RESPONSE, "session", token, SESSION_LIFETIME)
            return self._respond(REQUEST, {"ok": True})
        except (ValueError, UnicodeError, KeyError, TypeError, WebAuthnException) as exc:
            logger.info("WebAuthn authentication failed: %s", exc)
            return self._respond(REQUEST, {"error": "Passkey authentication failed."}, 400)

    security.declarePublic("remove_passkeys")
    def remove_passkeys(self, REQUEST):
        """Remove the current user's passkeys and revoke their passkey sessions."""
        try:
            self._request_data(REQUEST)
            user_id = self._current_user(REQUEST)
            for key, credential in list(self._credentials.items()):
                if credential["user_id"] == user_id:
                    del self._credentials[key]
            for key, session in list(self._sessions.items()):
                if session["user_id"] == user_id:
                    del self._sessions[key]
            for key, challenge in list(self._challenges.items()):
                if challenge["user_id"] == user_id:
                    del self._challenges[key]
            self._user_handles.pop(user_id, None)
            self._expire_cookie(REQUEST.RESPONSE, "session")
            return self._respond(REQUEST, {"ok": True})
        except (ValueError, UnicodeError) as exc:
            return self._respond(REQUEST, {"error": str(exc)}, 400)

    security.declarePrivate("extractCredentials")
    def extractCredentials(self, request):
        token = request.cookies.get(self._cookie_name("session"), "")
        user = self._session_user(token)
        if user is None:
            return {}
        return {"zms_webauthn_token": token, "login": user.getUserName()}

    def _session_user(self, token):
        if not isinstance(token, str):
            return None
        try:
            session = self._sessions.get(self._token_key(token))
        except UnicodeEncodeError:
            return None
        if not session or session["expires"] <= time.time():
            return None
        return aq_parent(self).getUserById(session["user_id"])

    security.declarePrivate("authenticateCredentials")
    def authenticateCredentials(self, credentials, request=None):
        user = self._session_user(credentials.get("zms_webauthn_token"))
        if user is None:
            return None
        return user.getId(), user.getUserName()

    security.declarePrivate("resetCredentials")
    def resetCredentials(self, request, response):
        token = request.cookies.get(self._cookie_name("session"), "")
        try:
            self._sessions.pop(self._token_key(token), None)
        except (UnicodeEncodeError, AttributeError):
            logger.info("Invalid WebAuthn session cookie during logout")
        self._expire_cookie(response, "session")


classImplements(
    ZMSPASWebauthn, IZMSPASWebauthn, IExtractionPlugin,
    IAuthenticationPlugin, ICredentialsResetPlugin,
)
InitializeClass(ZMSPASWebauthn)
