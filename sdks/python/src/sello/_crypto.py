from __future__ import annotations

import base64
import hashlib
import hmac
from dataclasses import dataclass
from typing import Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption


@dataclass(frozen=True)
class KeyPair:
    public_key: bytes
    private_key: bytes


def base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def base64url_decode(value: str, name: str = "value") -> bytes:
    if not value or any(char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-" for char in value):
        raise ValueError(f"{name} must be unpadded base64url")
    if len(value) % 4 == 1:
        raise ValueError(f"{name} must be unpadded base64url")
    return base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def generate_ed25519_key_pair() -> KeyPair:
    private = ed25519.Ed25519PrivateKey.generate()
    public = private.public_key()
    return KeyPair(
        public_key=public.public_bytes(Encoding.Raw, PublicFormat.Raw),
        private_key=private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()),
    )


def sign_ed25519(message: bytes, private_key: bytes) -> bytes:
    return ed25519.Ed25519PrivateKey.from_private_bytes(_expect_len(private_key, 32, "private_key")).sign(message)


def verify_ed25519(message: bytes, signature: bytes, public_key: bytes) -> bool:
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(_expect_len(public_key, 32, "public_key")).verify(signature, message)
        return True
    except Exception:
        return False


def generate_hpke_key_pair() -> KeyPair:
    private = x25519.X25519PrivateKey.generate()
    public = private.public_key()
    return KeyPair(
        public_key=public.public_bytes(Encoding.Raw, PublicFormat.Raw),
        private_key=private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()),
    )


def x25519_public_from_private(private_key: bytes) -> bytes:
    private = x25519.X25519PrivateKey.from_private_bytes(_expect_len(private_key, 32, "private_key"))
    return private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def seal_hpke_base(
    *,
    plaintext: bytes,
    aad: bytes,
    info: bytes,
    recipient_public_key: bytes,
    ephemeral_private_key: Optional[bytes] = None,
) -> bytes:
    ephemeral_private_key = ephemeral_private_key or generate_hpke_key_pair().private_key
    enc = x25519_public_from_private(ephemeral_private_key)
    shared_secret = _encap(ephemeral_private_key, recipient_public_key, enc)
    key, nonce = _key_schedule(shared_secret, info)
    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)
    return enc + ciphertext


def open_hpke_base(
    *,
    payload: bytes,
    aad: bytes,
    info: bytes,
    recipient_private_key: bytes,
) -> bytes:
    if len(payload) < 49:
        raise ValueError("HPKE payload must be at least 49 bytes")
    enc = payload[:32]
    ciphertext = payload[32:]
    recipient_public_key = x25519_public_from_private(recipient_private_key)
    shared_secret = _decap(enc, recipient_private_key, recipient_public_key)
    key, nonce = _key_schedule(shared_secret, info)
    return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)


def _encap(ephemeral_private_key: bytes, recipient_public_key: bytes, enc: bytes) -> bytes:
    dh = _x25519(ephemeral_private_key, recipient_public_key)
    return _extract_and_expand(dh, enc + recipient_public_key)


def _decap(enc: bytes, recipient_private_key: bytes, recipient_public_key: bytes) -> bytes:
    dh = _x25519(recipient_private_key, enc)
    return _extract_and_expand(dh, enc + recipient_public_key)


def _x25519(private_key: bytes, public_key: bytes) -> bytes:
    private = x25519.X25519PrivateKey.from_private_bytes(_expect_len(private_key, 32, "private_key"))
    public = x25519.X25519PublicKey.from_public_bytes(_expect_len(public_key, 32, "public_key"))
    shared = private.exchange(public)
    if shared == b"\x00" * 32:
        raise ValueError("X25519 shared secret must not be all zero")
    return shared


def _extract_and_expand(dh: bytes, kem_context: bytes) -> bytes:
    eae_prk = _labeled_extract(_KEM_SUITE_ID, b"", "eae_prk", dh)
    return _labeled_expand(_KEM_SUITE_ID, eae_prk, "shared_secret", kem_context, 32)


def _key_schedule(shared_secret: bytes, info: bytes) -> Tuple[bytes, bytes]:
    psk_id_hash = _labeled_extract(_HPKE_SUITE_ID, b"", "psk_id_hash", b"")
    info_hash = _labeled_extract(_HPKE_SUITE_ID, b"", "info_hash", info)
    key_schedule_context = b"\x00" + psk_id_hash + info_hash
    secret = _labeled_extract(_HPKE_SUITE_ID, shared_secret, "secret", b"")
    key = _labeled_expand(_HPKE_SUITE_ID, secret, "key", key_schedule_context, 32)
    nonce = _labeled_expand(_HPKE_SUITE_ID, secret, "base_nonce", key_schedule_context, 12)
    return key, nonce


def _labeled_extract(suite_id: bytes, salt: bytes, label: str, ikm: bytes) -> bytes:
    return _hkdf_extract(salt, b"HPKE-v1" + suite_id + label.encode("ascii") + ikm)


def _labeled_expand(suite_id: bytes, prk: bytes, label: str, info: bytes, length: int) -> bytes:
    return _hkdf_expand(prk, length.to_bytes(2, "big") + b"HPKE-v1" + suite_id + label.encode("ascii") + info, length)


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    key = salt or (b"\x00" * 32)
    return hmac.new(key, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    blocks: list[bytes] = []
    previous = b""
    counter = 1
    while len(b"".join(blocks)) < length:
        previous = hmac.new(prk, previous + info + bytes([counter]), hashlib.sha256).digest()
        blocks.append(previous)
        counter += 1
    return b"".join(blocks)[:length]


def _expect_len(data: bytes, length: int, name: str) -> bytes:
    if not isinstance(data, bytes) or len(data) != length:
        raise ValueError(f"{name} must be {length} bytes")
    return data


def _i2osp(value: int, length: int) -> bytes:
    return value.to_bytes(length, "big")


_KEM_SUITE_ID = b"KEM" + _i2osp(0x0020, 2)
_HPKE_SUITE_ID = b"HPKE" + _i2osp(0x0020, 2) + _i2osp(0x0001, 2) + _i2osp(0x0003, 2)
