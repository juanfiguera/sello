from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Optional, Tuple, Union

import cbor2

from ._crypto import open_hpke_base, seal_hpke_base, sha256, sign_ed25519, verify_ed25519
from .logs import MemoryLog, TransparencyLogEntry
from .token import verify_sello_jws_token


@dataclass(frozen=True)
class BuiltReceipt:
    receipt_body: dict[str, Any]
    protected_header_bytes: bytes
    envelope: bytes


@dataclass(frozen=True)
class CreatedReceipt(BuiltReceipt):
    log_entry: TransparencyLogEntry


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def derive_token_identifiers(token_bytes: bytes) -> tuple[bytes, str]:
    digest = sha256(token_bytes)
    return digest, digest[:16].hex()


def build_receipt(
    *,
    authorization_token_bytes: bytes,
    owner_hpke_public_key: bytes,
    sello_logs: list[str],
    service_kid: bytes,
    service_private_key: bytes,
    service_identifier: str,
    log_url: str,
    action_type: str,
    action_input_bytes: bytes,
    action_output_bytes: bytes,
    result_status: str,
    timestamp: str,
) -> BuiltReceipt:
    if log_url not in sello_logs:
        raise ValueError("service log must be listed in sello_logs")
    token_ref, agent_identifier = derive_token_identifiers(authorization_token_bytes)
    output_hash = b"\x00" * 32 if result_status == "denied" else sha256(action_output_bytes)
    receipt_body = {
        "agent-identifier": agent_identifier,
        "action-type": action_type,
        "action-input-hash": sha256(action_input_bytes),
        "action-output-hash": output_hash,
        "result-status": result_status,
        "timestamp": timestamp,
    }
    protected_header_bytes = cbor2.dumps(
        {
            1: -8,
            4: service_kid,
            -65537: "0.1.0",
            -65538: token_ref,
            -65539: log_url,
        },
        canonical=True,
    )
    plaintext = cbor2.dumps(
        {
            "agent-identifier": agent_identifier,
            "action-type": action_type,
            "action-input-hash": receipt_body["action-input-hash"],
            "action-output-hash": output_hash,
            "result-status": result_status,
            "timestamp": cbor2.CBORTag(0, timestamp),
        },
        canonical=True,
    )
    payload = seal_hpke_base(
        plaintext=plaintext,
        aad=protected_header_bytes,
        info=_receipt_hpke_info(service_identifier, token_ref),
        recipient_public_key=owner_hpke_public_key,
    )
    envelope = sign_receipt_envelope(
        protected_header_bytes=protected_header_bytes,
        payload=payload,
        service_private_key=service_private_key,
    )
    return BuiltReceipt(receipt_body, protected_header_bytes, envelope)


def create_receipt_from_jws_token(
    *,
    authorization_token: Union[str, bytes],
    token_issuer_public_key: bytes,
    service_kid: bytes,
    service_private_key: bytes,
    service_identifier: str,
    log: MemoryLog,
    action_type: str,
    action_input_bytes: bytes,
    action_output_bytes: bytes,
    result_status: str,
    timestamp: str,
    fallback_sello_logs: Optional[list[str]] = None,
) -> CreatedReceipt:
    verified = verify_sello_jws_token(authorization_token, token_issuer_public_key)
    built = build_receipt(
        authorization_token_bytes=verified.authorization_token_bytes,
        owner_hpke_public_key=verified.owner_hpke_public_key,
        sello_logs=verified.sello_logs or fallback_sello_logs or [],
        service_kid=service_kid,
        service_private_key=service_private_key,
        service_identifier=service_identifier,
        log_url=log.log_url,
        action_type=action_type,
        action_input_bytes=action_input_bytes,
        action_output_bytes=action_output_bytes,
        result_status=result_status,
        timestamp=timestamp,
    )
    entry = log.append(built.envelope, timestamp)
    return CreatedReceipt(built.receipt_body, built.protected_header_bytes, built.envelope, entry)


def sign_receipt_envelope(*, protected_header_bytes: bytes, payload: bytes, service_private_key: bytes) -> bytes:
    signature = sign_ed25519(_sig_structure(protected_header_bytes, payload), service_private_key)
    return cbor2.dumps([protected_header_bytes, {}, payload, signature], canonical=True)


def verify_receipt_envelope(envelope: bytes, service_public_key: bytes) -> Tuple[bytes, bytes, bytes]:
    protected, unprotected, payload, signature = cbor2.loads(envelope)
    if unprotected != {}:
        raise ValueError("COSE_Sign1 unprotected header must be empty")
    if not verify_ed25519(_sig_structure(protected, payload), signature, service_public_key):
        raise ValueError("COSE_Sign1 signature verification failed")
    return protected, payload, signature


def open_receipt_body(*, payload: bytes, protected_header_bytes: bytes, service_identifier: str, authorization_token_bytes: bytes, owner_private_key: bytes) -> dict[str, Any]:
    token_ref, _ = derive_token_identifiers(authorization_token_bytes)
    plaintext = open_hpke_base(
        payload=payload,
        aad=protected_header_bytes,
        info=_receipt_hpke_info(service_identifier, token_ref),
        recipient_private_key=owner_private_key,
    )
    return cbor2.loads(plaintext)


def _sig_structure(protected_header_bytes: bytes, payload: bytes) -> bytes:
    return cbor2.dumps(["Signature1", protected_header_bytes, b"", payload], canonical=True)


def _receipt_hpke_info(service_identifier: str, token_ref: bytes) -> bytes:
    return cbor2.dumps(["sello/0.1.0/receipt", service_identifier, token_ref], canonical=True)
