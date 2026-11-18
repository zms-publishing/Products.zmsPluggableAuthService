import base64
import hashlib
import json
import unittest
from unittest.mock import patch

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from Products.PluggableAuthService.interfaces.plugins import (
    IAuthenticationPlugin, IExtractionPlugin, IUserEnumerationPlugin,
)
from Products.PluggableAuthService.PluggableAuthService import PluggableAuthService, _PLUGIN_TYPE_INFO
from Products.PluggableAuthService.plugins.ZODBUserManager import ZODBUserManager
from Products.PluginRegistry.PluginRegistry import PluginRegistry
from ZPublisher.HTTPResponse import HTTPResponse

from Products.zmsPluggableAuthService.plugins.ZMSPASWebauthn import ZMSPASWebauthn


def b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


class Request(dict):
    def __init__(self, data, user=None, cookies=None, origin="https://example.com"):
        super().__init__(
            REQUEST_METHOD="POST", HTTP_ORIGIN=origin,
            CONTENT_TYPE="application/json", BODY=json.dumps(data).encode(),
            AUTHENTICATED_USER=user,
        )
        self.cookies = cookies or {}
        self.RESPONSE = HTTPResponse()

    def _authUserPW(self):
        return None


class WebAuthnTests(unittest.TestCase):
    def setUp(self):
        self.pas = PluggableAuthService("acl_users")
        registry = PluginRegistry(plugin_type_info=_PLUGIN_TYPE_INFO)
        registry._setId("plugins")
        self.pas._setObject("plugins", registry)
        self.pas._setObject("users", ZODBUserManager("users"))
        self.pas.plugins.activatePlugin(IUserEnumerationPlugin, "users")
        self.pas.users.addUser("alice-id", "alice-login", "password")
        self.pas._setObject(
            "passkeys", ZMSPASWebauthn("passkeys", "Passkeys", "example.com", "https://example.com")
        )
        self.plugin = self.pas.passkeys
        self.pas.plugins.activatePlugin(IExtractionPlugin, "passkeys")
        self.pas.plugins.activatePlugin(IAuthenticationPlugin, "passkeys")
        self.user = self.pas.getUserById("alice-id")
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = b"test-credential-id"

    def call(self, endpoint, data, user=None, cookies=None, origin="https://example.com"):
        request = Request(data, user, cookies, origin)
        result = json.loads(getattr(self.plugin, endpoint)(request))
        return request, result

    def cookie(self, request, kind):
        name = self.plugin._cookie_name(kind)
        return {name: request.RESPONSE.cookies[name]["value"]}

    def client_data(self, operation, challenge, origin="https://example.com"):
        return json.dumps({
            "type": operation, "challenge": challenge, "origin": origin,
        }, separators=(",", ":")).encode()

    def register(self):
        request, options = self.call("registration_options", {}, self.user)
        self.assertEqual(request.RESPONSE.getStatus(), 200)
        client = self.client_data("webauthn.create", options["challenge"])
        numbers = self.key.public_key().public_numbers()
        cose_key = cbor2.dumps({
            1: 2, 3: -7, -1: 1, -2: numbers.x.to_bytes(32, "big"),
            -3: numbers.y.to_bytes(32, "big"),
        })
        auth_data = (
            hashlib.sha256(b"example.com").digest() + b"\x45" + b"\0" * 4
            + b"\0" * 16 + len(self.credential_id).to_bytes(2, "big")
            + self.credential_id + cose_key
        )
        payload = {
            "id": b64(self.credential_id), "rawId": b64(self.credential_id),
            "type": "public-key", "response": {
                "clientDataJSON": b64(client),
                "attestationObject": b64(cbor2.dumps({
                    "fmt": "none", "attStmt": {}, "authData": auth_data,
                })),
            },
        }
        finish, result = self.call(
            "registration_finish", payload, self.user, self.cookie(request, "challenge")
        )
        self.assertEqual(finish.RESPONSE.getStatus(), 200, result)
        return payload, self.cookie(request, "challenge")

    def assertion(self, challenge, count=1, key=None, origin="https://example.com", flags=b"\x05"):
        client = self.client_data("webauthn.get", challenge, origin)
        auth_data = hashlib.sha256(b"example.com").digest() + flags + count.to_bytes(4, "big")
        signature = (key or self.key).sign(
            auth_data + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256())
        )
        return {
            "id": b64(self.credential_id), "rawId": b64(self.credential_id),
            "type": "public-key", "response": {
                "clientDataJSON": b64(client), "authenticatorData": b64(auth_data),
                "signature": b64(signature),
            },
        }

    def test_registration_login_replay_and_logout(self):
        payload, registration_cookie = self.register()
        replay, _ = self.call("registration_finish", payload, self.user, registration_cookie)
        self.assertEqual(replay.RESPONSE.getStatus(), 400)
        self.assertEqual(self.plugin.login_form._v_errors, ())
        start, options = self.call("authentication_options", {"user_id": "alice-id"})
        assertion = self.assertion(options["challenge"])
        challenge_cookie = self.cookie(start, "challenge")
        finish, result = self.call("authentication_finish", assertion, cookies=challenge_cookie)
        self.assertEqual(finish.RESPONSE.getStatus(), 200, result)
        self.assertEqual(self.plugin._credentials[self.credential_id]["sign_count"], 1)
        cookie = self.cookie(finish, "session")
        name = self.plugin._cookie_name("session")
        self.assertTrue(finish.RESPONSE.cookies[name]["Secure"])
        self.assertTrue(finish.RESPONSE.cookies[name]["HttpOnly"])
        self.assertEqual(finish.RESPONSE.cookies[name]["SameSite"], "Strict")
        request = Request({}, cookies=cookie)
        credentials = self.plugin.extractCredentials(request)
        self.assertEqual(self.plugin.authenticateCredentials(credentials), ("alice-id", "alice-login"))
        self.assertEqual(self.pas._extractUserIds(request, self.pas.plugins), [("alice-id", "alice-login")])
        replay, _ = self.call("authentication_finish", assertion, cookies=challenge_cookie)
        self.assertEqual(replay.RESPONSE.getStatus(), 400)
        self.plugin.resetCredentials(request, request.RESPONSE)
        self.assertIsNone(self.plugin.authenticateCredentials(credentials))
        self.assertEqual(self.plugin.extractCredentials(request), {})
        self.assertEqual(self.pas._extractUserIds(request, self.pas.plugins), [])

    def test_enrollment_requires_same_authenticated_pas_user_and_origin(self):
        request, _ = self.call("registration_options", {})
        self.assertEqual(request.RESPONSE.getStatus(), 400)
        request, _ = self.call("registration_options", {}, self.user, origin="https://evil.example")
        self.assertEqual(request.RESPONSE.getStatus(), 400)
        request, _ = self.call("registration_options", {}, self.user)
        finish, _ = self.call("registration_finish", {}, cookies=self.cookie(request, "challenge"))
        self.assertEqual(finish.RESPONSE.getStatus(), 400)

    def test_rejects_bad_signature_and_consumes_challenge(self):
        self.register()
        start, options = self.call("authentication_options", {"user_id": "alice-id"})
        cookie = self.cookie(start, "challenge")
        bad = self.assertion(options["challenge"], key=ec.generate_private_key(ec.SECP256R1()))
        finish, _ = self.call("authentication_finish", bad, cookies=cookie)
        self.assertEqual(finish.RESPONSE.getStatus(), 400)
        valid = self.assertion(options["challenge"])
        replay, _ = self.call("authentication_finish", valid, cookies=cookie)
        self.assertEqual(replay.RESPONSE.getStatus(), 400)
        self.assertEqual(self.plugin._credentials[self.credential_id]["sign_count"], 0)

    def test_rejects_wrong_client_origin_and_missing_user_verification(self):
        self.register()
        for kwargs in ({"origin": "https://evil.example"}, {"flags": b"\x01"}):
            with self.subTest(kwargs=kwargs):
                start, options = self.call("authentication_options", {"user_id": "alice-id"})
                finish, _ = self.call(
                    "authentication_finish", self.assertion(options["challenge"], **kwargs),
                    cookies=self.cookie(start, "challenge"),
                )
                self.assertEqual(finish.RESPONSE.getStatus(), 400)

    def test_removing_passkeys_revokes_sessions_and_pending_challenges(self):
        self.register()
        start, options = self.call("authentication_options", {"user_id": "alice-id"})
        finish, _ = self.call(
            "authentication_finish", self.assertion(options["challenge"]),
            cookies=self.cookie(start, "challenge"),
        )
        credentials = self.plugin.extractCredentials(Request({}, cookies=self.cookie(finish, "session")))
        pending, _ = self.call("authentication_options", {"user_id": "alice-id"})
        denied, _ = self.call("remove_passkeys", {})
        self.assertEqual(denied.RESPONSE.getStatus(), 400)
        removed, _ = self.call("remove_passkeys", {}, self.user)
        self.assertEqual(removed.RESPONSE.getStatus(), 200)
        self.assertIsNone(self.plugin.authenticateCredentials(credentials))
        self.assertEqual(
            self.plugin.extractCredentials(Request({}, cookies=self.cookie(finish, "session"))), {}
        )
        self.assertFalse(self.plugin._credentials)
        self.assertFalse(self.plugin._challenges)
        replay, _ = self.call(
            "authentication_finish", self.assertion(options["challenge"]),
            cookies=self.cookie(pending, "challenge"),
        )
        self.assertEqual(replay.RESPONSE.getStatus(), 400)

    def test_expired_challenge_is_rejected(self):
        self.register()
        start, options = self.call("authentication_options", {"user_id": "alice-id"})
        with patch("Products.zmsPluggableAuthService.plugins.ZMSPASWebauthn.time.time", return_value=10**11):
            finish, _ = self.call(
                "authentication_finish", self.assertion(options["challenge"]),
                cookies=self.cookie(start, "challenge"),
            )
        self.assertEqual(finish.RESPONSE.getStatus(), 400)

    def test_rejects_insecure_or_mismatched_configuration(self):
        for rp_id, origin in [
            ("example.com", "http://example.com"),
            ("example.com", "https://attacker.com"),
            ("example.com", "https://example.com/path"),
        ]:
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                ZMSPASWebauthn("passkeys", "", rp_id, origin)


if __name__ == "__main__":
    unittest.main()
