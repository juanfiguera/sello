import importlib.util
import os
from pathlib import Path
import unittest
from unittest.mock import patch

import sello
from sello.receipt import open_receipt_body, verify_receipt_envelope
from sello.token import sign_sello_jws_token


SERVICE_ID = "calendar.example.com/mcp/v1"
ACTION_TYPE = "calendar.create_event"
TIMESTAMP = "2026-06-13T10:00:00Z"


class SelloPythonSdkTests(unittest.TestCase):
    def test_wraps_tool_and_emits_decryptable_success_receipt(self):
        fixture = make_fixture()
        events = []
        receipts = sello.service(
            {
                **fixture.service_config(),
                "submit": "await",
                "on_receipt": events.append,
            }
        )

        @receipts.tool(ACTION_TYPE)
        def create_event(request):
            return {"ok": True, "id": request["params"]["title"]}

        response = create_event(fixture.request())
        body = fixture.decrypt_first_receipt()

        self.assertEqual(response, {"ok": True, "id": "launch"})
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["result_status"], "success")
        self.assertEqual(body["action-type"], ACTION_TYPE)
        self.assertEqual(body["result-status"], "success")

    def test_explicit_wrapper_emits_error_and_rethrows(self):
        fixture = make_fixture()
        receipts = sello.service({**fixture.service_config(), "submit": "await"})

        def create_event(_request):
            raise RuntimeError("calendar exploded")

        wrapped = receipts.tool(ACTION_TYPE, create_event)

        with self.assertRaisesRegex(RuntimeError, "calendar exploded"):
            wrapped(fixture.request())

        body = fixture.decrypt_first_receipt()
        self.assertEqual(body["result-status"], "error")

    def test_denied_receipt_can_return_custom_response(self):
        fixture = make_fixture()
        called = False
        receipts = sello.service({**fixture.service_config(), "submit": "await"})

        @receipts.tool(
            ACTION_TYPE,
            is_denied=lambda _request: True,
            denied_response=lambda _request: {"ok": False},
        )
        def create_event(_request):
            nonlocal called
            called = True
            return {"ok": True}

        response = create_event(fixture.request())
        body = fixture.decrypt_first_receipt()

        self.assertFalse(called)
        self.assertEqual(response, {"ok": False})
        self.assertEqual(body["result-status"], "denied")
        self.assertEqual(body["action-output-hash"], b"\x00" * 32)

    def test_verifies_token_before_running_tool(self):
        fixture = make_fixture()
        other_issuer = sello.generate_ed25519_key_pair()
        bad_token = sign_sello_jws_token(
            issuer_private_key=other_issuer.private_key,
            payload={
                "sub": "demo-agent",
                "owner_hpke_pk": sello.base64url_encode(fixture.owner.public_key),
                "sello_logs": [fixture.log.log_url],
            },
        )
        called = False
        receipts = sello.service({**fixture.service_config(), "submit": "await"})

        @receipts.tool(ACTION_TYPE)
        def create_event(_request):
            nonlocal called
            called = True
            return {"ok": True}

        with self.assertRaisesRegex(ValueError, "signature verification failed"):
            create_event({**fixture.request(), "authorizationToken": bad_token})

        self.assertFalse(called)
        self.assertEqual(len(fixture.log.entries), 0)

    def test_background_drop_calls_on_drop(self):
        fixture = make_fixture()
        drops = []
        receipts = sello.service(
            {
                **fixture.service_config(),
                "submit": {"mode": "background", "max_pending": 0},
                "on_drop": drops.append,
            }
        )

        @receipts.tool(ACTION_TYPE)
        def create_event(_request):
            return {"ok": True}

        create_event(fixture.request())
        receipts.flush()

        self.assertEqual(len(drops), 1)
        self.assertEqual(drops[0]["reason"], "queue_full")
        self.assertEqual(len(fixture.log.entries), 0)

    def test_loads_service_config_from_env(self):
        fixture = make_fixture()
        env = {
            "SELLO_SERVICE_ID": SERVICE_ID,
            "SELLO_SERVICE_KEY": sello.encode_service_key(fixture.kid, fixture.service.private_key),
            "SELLO_TOKEN_ISSUER_PUBLIC_KEY": sello.base64url_encode(fixture.issuer.public_key),
            "SELLO_LOG_URL": fixture.log.log_url,
            "SELLO_SUBMIT_MODE": "await",
        }
        with patch.dict(os.environ, env, clear=True):
            receipts = sello.service(log=fixture.log, now=lambda: TIMESTAMP)
            wrapped = receipts.tool(ACTION_TYPE, lambda _request: {"ok": True})
            wrapped(fixture.request())

        self.assertEqual(fixture.decrypt_first_receipt()["result-status"], "success")

    def test_package_exposes_version(self):
        self.assertRegex(sello.__version__, r"^\d+\.\d+\.\d+")

    def test_quickstart_example_emits_receipt_without_live_server(self):
        fixture = make_fixture()
        example = load_quickstart_example()

        result = example.run_quickstart_tool(
            state={
                "serviceId": SERVICE_ID,
                "serviceKey": sello.encode_service_key(
                    fixture.kid,
                    fixture.service.private_key,
                ),
                "tokenIssuerPublicKey": sello.base64url_encode(fixture.issuer.public_key),
                "agentToken": fixture.authorization_token,
                "logUrl": fixture.log.log_url,
                "logEndpoint": "http://localhost:8787/api",
            },
            log=fixture.log,
            now=lambda: TIMESTAMP,
            request={"title": "Review launch plan"},
        )
        body = fixture.decrypt_first_receipt()

        self.assertEqual(result["response"]["id"], "evt_review_launch_plan")
        self.assertEqual(result["response"]["status"], "created")
        self.assertEqual(result["actionsUrl"], "http://localhost:8787/actions")
        self.assertEqual(body["action-type"], ACTION_TYPE)
        self.assertEqual(body["result-status"], "success")


class Fixture:
    def __init__(self):
        self.owner = sello.generate_hpke_key_pair()
        self.service = sello.generate_ed25519_key_pair()
        self.issuer = sello.generate_ed25519_key_pair()
        self.kid = b"calendar-2026-q2"
        self.log = sello.logs.memory("https://localhost:8787/api")
        self.authorization_token = sign_sello_jws_token(
            issuer_private_key=self.issuer.private_key,
            payload={
                "sub": "demo-agent",
                "owner_hpke_pk": sello.base64url_encode(self.owner.public_key),
                "sello_logs": [self.log.log_url],
            },
        )

    def service_config(self):
        return {
            "service": SERVICE_ID,
            "service_key": sello.encode_service_key(self.kid, self.service.private_key),
            "token_issuer": self.issuer.public_key,
            "log": self.log,
            "now": lambda: TIMESTAMP,
        }

    def request(self):
        return {
            "authorizationToken": self.authorization_token,
            "params": {"title": "launch"},
        }

    def decrypt_first_receipt(self):
        self.assert_has_receipt()
        entry = self.log.entries[0]
        protected, payload, _signature = verify_receipt_envelope(
            entry.envelope,
            self.service.public_key,
        )
        return open_receipt_body(
            payload=payload,
            protected_header_bytes=protected,
            service_identifier=SERVICE_ID,
            authorization_token_bytes=self.authorization_token.encode("ascii"),
            owner_private_key=self.owner.private_key,
        )

    def assert_has_receipt(self):
        if not self.log.entries:
            raise AssertionError("expected one receipt")


def make_fixture():
    return Fixture()


def load_quickstart_example():
    path = Path(__file__).resolve().parents[1] / "examples" / "quickstart_tool.py"
    spec = importlib.util.spec_from_file_location("sello_python_quickstart_tool", path)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load Python quickstart example")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


if __name__ == "__main__":
    unittest.main()
