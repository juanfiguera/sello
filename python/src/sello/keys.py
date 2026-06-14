from __future__ import annotations

from typing import Optional, Tuple, Union

from ._crypto import (
    KeyPair,
    base64url_decode,
    base64url_encode,
    generate_ed25519_key_pair,
    generate_hpke_key_pair,
)


def encode_service_key(kid: bytes, private_key: bytes, prefix: str = "sello_dev") -> str:
    if not kid:
        raise ValueError("kid must not be empty")
    _expect_len(private_key, 32, "private_key")
    return f"{prefix}_{base64url_encode(kid)}.{base64url_encode(private_key)}"


def encode_owner_key(private_key: bytes, prefix: str = "sello_owner_dev") -> str:
    _expect_len(private_key, 32, "private_key")
    return f"{prefix}_{base64url_encode(private_key)}"


def normalize_service_key(value: Union[str, dict[str, object]], fallback_kid: Optional[Union[str, bytes]] = None) -> Tuple[bytes, bytes]:
    if isinstance(value, dict):
        kid = normalize_kid(value.get("kid"), "service_key.kid")
        private_key = normalize_ed25519_private_key(value.get("private_key"), "service_key.private_key")
        return kid, private_key

    if not isinstance(value, str):
        raise ValueError("service_key must be a string or dict")

    encoded = _strip_service_prefix(value)
    if "." in encoded:
        encoded_kid, encoded_private = encoded.split(".", 1)
        return base64url_decode(encoded_kid, "service key kid"), normalize_ed25519_private_key(encoded_private)

    if fallback_kid is None:
        raise ValueError("service key must include a kid, or service_kid must be set")

    return normalize_kid(fallback_kid, "service_kid"), normalize_ed25519_private_key(encoded)


def normalize_kid(value: object, name: str = "kid") -> bytes:
    if isinstance(value, bytes):
        if not value:
            raise ValueError(f"{name} must not be empty")
        return bytes(value)
    if isinstance(value, str) and value:
        return value.encode("utf-8")
    raise ValueError(f"{name} must be a non-empty string or bytes")


def normalize_ed25519_private_key(value: object, name: str = "private_key") -> bytes:
    return _normalize_fixed_key(value, 32, name)


def normalize_ed25519_public_key(value: object, name: str = "public_key") -> bytes:
    return _normalize_fixed_key(value, 32, name)


def normalize_hpke_private_key(value: object, name: str = "owner_private_key") -> bytes:
    if isinstance(value, str):
        for prefix in ("sello_owner_dev_", "sello_owner_live_"):
            if value.startswith(prefix):
                value = value[len(prefix):]
                break
    return _normalize_fixed_key(value, 32, name)


def _normalize_fixed_key(value: object, length: int, name: str) -> bytes:
    if isinstance(value, bytes):
        return _expect_len(value, length, name)
    if isinstance(value, str):
        return _expect_len(base64url_decode(value, name), length, name)
    raise ValueError(f"{name} must be a string or bytes")


def _expect_len(value: bytes, length: int, name: str) -> bytes:
    if len(value) != length:
        raise ValueError(f"{name} must be {length} bytes")
    return value


def _strip_service_prefix(value: str) -> str:
    for prefix in ("sello_dev_", "sello_live_local_"):
        if value.startswith(prefix):
            return value[len(prefix):]
    return value
