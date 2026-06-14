from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from ._crypto import base64url_decode, base64url_encode


@dataclass(frozen=True)
class TransparencyLogEntry:
    log_url: str
    index: int
    integrated_time: str
    envelope: bytes
    proof: Any


class MemoryLog:
    def __init__(self, url: str):
        self.log_url = to_canonical_log_url(url)
        self.entries: list[TransparencyLogEntry] = []

    def append(self, envelope: bytes, integrated_time: Optional[str] = None) -> TransparencyLogEntry:
        entry = TransparencyLogEntry(
            log_url=self.log_url,
            index=len(self.entries),
            integrated_time=integrated_time or _now_utc_seconds(),
            envelope=bytes(envelope),
            proof={"type": "memory", "index": len(self.entries)},
        )
        self.entries.append(entry)
        return entry


class HttpLog:
    def __init__(self, url: str, *, endpoint: Optional[str] = None, headers: Optional[dict[str, str]] = None):
        self.log_url = to_canonical_log_url(url)
        self.endpoint = _normalize_endpoint(endpoint or url)
        self.headers = headers or {}

    def append(self, envelope: bytes, integrated_time: Optional[str] = None) -> TransparencyLogEntry:
        body = {
            "logUrl": self.log_url,
            "envelope": base64url_encode(bytes(envelope)),
        }
        if integrated_time is not None:
            body["integratedTime"] = integrated_time

        request = Request(
            _join_url(self.endpoint, "/entries"),
            data=json.dumps(body).encode("utf-8"),
            method="POST",
            headers={"content-type": "application/json", **self.headers},
        )
        with urlopen(request) as response:
            return deserialize_entry(json.loads(response.read().decode("utf-8")))


def memory(url: str) -> MemoryLog:
    return MemoryLog(url)


def http(url: str, *, endpoint: Optional[str] = None, headers: Optional[dict[str, str]] = None) -> HttpLog:
    return HttpLog(url, endpoint=endpoint, headers=headers)


def serialize_entry(entry: TransparencyLogEntry) -> dict[str, Any]:
    return {
        "logUrl": entry.log_url,
        "index": entry.index,
        "integratedTime": entry.integrated_time,
        "envelope": base64url_encode(entry.envelope),
        "proof": entry.proof,
    }


def deserialize_entry(value: dict[str, Any]) -> TransparencyLogEntry:
    return TransparencyLogEntry(
        log_url=to_canonical_log_url(value["logUrl"]),
        index=int(value["index"]),
        integrated_time=str(value["integratedTime"]),
        envelope=base64url_decode(str(value["envelope"]), "entry.envelope"),
        proof=value.get("proof"),
    )


def to_canonical_log_url(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("log URL must be absolute")
    scheme = "https" if parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"} else parsed.scheme
    path = parsed.path if parsed.path and parsed.path != "/" else "/api"
    canonical = f"{scheme}://{parsed.netloc}{path}"
    if scheme != "https":
        raise ValueError("log URL must use https")
    if canonical.endswith("/") or parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise ValueError("log URL must be canonical")
    return canonical


def _normalize_endpoint(url: str) -> str:
    parsed = urlparse(url)
    path = parsed.path if parsed.path and parsed.path != "/" else "/api"
    return f"{parsed.scheme}://{parsed.netloc}{path.rstrip('/')}"


def _join_url(endpoint: str, path: str) -> str:
    return f"{endpoint.rstrip('/')}{path}"


def _now_utc_seconds() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
