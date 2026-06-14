from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Optional, Union

from ._crypto import base64url_decode, base64url_encode, sign_ed25519, verify_ed25519
from .logs import to_canonical_log_url


@dataclass(frozen=True)
class VerifiedSelloToken:
    authorization_token_bytes: bytes
    owner_hpke_public_key: bytes
    sello_logs: Optional[list[str]]
    protected_header: dict[str, Any]
    payload: dict[str, Any]


def sign_sello_jws_token(*, payload: dict[str, Any], issuer_private_key: bytes, protected_header: Optional[dict[str, Any]] = None) -> str:
    header = {"alg": "EdDSA", "typ": "JWT", **(protected_header or {})}
    encoded_header = base64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    encoded_payload = base64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
    signature = sign_ed25519(signing_input, issuer_private_key)
    return f"{encoded_header}.{encoded_payload}.{base64url_encode(signature)}"


def verify_sello_jws_token(authorization_token: Union[str, bytes], issuer_public_key: bytes) -> VerifiedSelloToken:
    token_bytes = authorization_token.encode("ascii") if isinstance(authorization_token, str) else bytes(authorization_token)
    token = token_bytes.decode("ascii")
    parts = token.split(".")
    if len(parts) != 3 or any(not part for part in parts):
        raise ValueError("authorization token must be compact JWS")
    encoded_header, encoded_payload, encoded_signature = parts
    header = _json_object(base64url_decode(encoded_header, "JWS protected header"), "JWS protected header")
    if header.get("alg") != "EdDSA":
        raise ValueError("JWS alg must be EdDSA")
    if "crit" in header:
        raise ValueError("JWS crit is not supported")
    signature = base64url_decode(encoded_signature, "JWS signature")
    if not verify_ed25519(f"{encoded_header}.{encoded_payload}".encode("ascii"), signature, issuer_public_key):
        raise ValueError("JWS signature verification failed")
    payload = _json_object(base64url_decode(encoded_payload, "JWS payload"), "JWS payload")
    owner_key = payload.get("owner_hpke_pk")
    if not isinstance(owner_key, str):
        raise ValueError("owner_hpke_pk must be a string")
    owner_hpke_public_key = base64url_decode(owner_key, "owner_hpke_pk")
    if len(owner_hpke_public_key) != 32:
        raise ValueError("owner_hpke_pk must encode a raw 32-byte X25519 public key")
    logs_value = payload.get("sello_logs")
    sello_logs = None
    if logs_value is not None:
        if not isinstance(logs_value, list):
            raise ValueError("sello_logs must be an array")
        sello_logs = [to_canonical_log_url(entry) for entry in logs_value]
    return VerifiedSelloToken(token_bytes, owner_hpke_public_key, sello_logs, header, payload)


def _json_object(data: bytes, name: str) -> dict[str, Any]:
    value = json.loads(data.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{name} must be a JSON object")
    return value
