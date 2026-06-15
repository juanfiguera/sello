from importlib.metadata import PackageNotFoundError, version

from . import logs
from .keys import (
    KeyPair,
    base64url_decode,
    base64url_encode,
    encode_owner_key,
    encode_service_key,
    generate_ed25519_key_pair,
    generate_hpke_key_pair,
    normalize_service_key,
)
from .service import SelloDeniedError, SelloReceipts, service
from .token import sign_sello_jws_token, verify_sello_jws_token

try:
    __version__ = version("sello")
except PackageNotFoundError:
    __version__ = "0.1.12"

__all__ = [
    "KeyPair",
    "SelloDeniedError",
    "SelloReceipts",
    "__version__",
    "base64url_decode",
    "base64url_encode",
    "encode_owner_key",
    "encode_service_key",
    "generate_ed25519_key_pair",
    "generate_hpke_key_pair",
    "logs",
    "normalize_service_key",
    "service",
    "sign_sello_jws_token",
    "verify_sello_jws_token",
]
