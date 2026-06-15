#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

import sello
from sello.receipt import canonical_json_bytes


DEFAULT_REQUEST = {
    "calendarId": "demo-calendar",
    "title": "Review launch plan",
    "start": "2026-06-05T17:00:00Z",
    "attendees": ["ada@example.com", "grace@example.com"],
}


def run_quickstart_tool(
    *,
    state: Optional[dict[str, Any]] = None,
    state_path: Optional[str] = None,
    log: Any = None,
    now: Any = None,
    request: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    dev_state = state or load_quickstart_dev_state(state_path)
    receipts = sello.service(
        {
            "service": read_string(dev_state, "serviceId"),
            "service_key": read_string(dev_state, "serviceKey"),
            "token_issuer": read_string(dev_state, "tokenIssuerPublicKey"),
            "log": log
            or sello.logs.http(
                read_string(dev_state, "logUrl"),
                endpoint=read_string(dev_state, "logEndpoint"),
            ),
            "submit": "await",
            "now": now,
        }
    )

    @receipts.tool(
        "calendar.create_event",
        canonicalize_input=lambda value: canonical_json_bytes(
            {
                "calendarId": value["calendarId"],
                "title": value["title"],
                "start": value["start"],
                "attendees": value["attendees"],
            }
        ),
    )
    def create_event(value: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": f"evt_{slug(value['title'])}",
            "calendarId": value["calendarId"],
            "title": value["title"],
            "status": "created",
            "createdAt": datetime.now(timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
        }

    event_request = {
        **DEFAULT_REQUEST,
        **(request or {}),
        "authorizationToken": read_string(dev_state, "agentToken"),
    }
    response = create_event(event_request)
    receipts.flush()

    return {
        "request": event_request,
        "response": response,
        "actionsUrl": action_viewer_url(read_string(dev_state, "logEndpoint")),
    }


def load_quickstart_dev_state(state_path: Optional[str] = None) -> dict[str, Any]:
    path = Path(state_path or ".sello/dev.json")
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise RuntimeError(
            "missing local Sello dev state. Start the local log with `npx sello dev`, "
            "then run this example in another terminal."
        ) from error

    if not isinstance(parsed, dict):
        raise TypeError("local Sello dev state must be a JSON object")
    return parsed


def action_viewer_url(log_endpoint: str) -> str:
    parsed = urlparse(log_endpoint)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("logEndpoint must be an absolute URL")
    return f"{parsed.scheme}://{parsed.netloc}/actions"


def read_string(value: dict[str, Any], key: str) -> str:
    entry = value.get(key)
    if not isinstance(entry, str) or not entry:
        raise ValueError(f"dev state {key} must be a non-empty string")
    return entry


def slug(value: str) -> str:
    return re.sub(r"(^_+|_+$)", "", re.sub(r"[^a-z0-9]+", "_", value.lower()))[:40]


def main() -> int:
    try:
        result = run_quickstart_tool()
    except Exception as error:
        print(f"sello quickstart: {error}", file=sys.stderr)
        return 1

    print("Created example event and emitted a Sello receipt.")
    print(json.dumps(result["response"], indent=2))
    print()
    print("View verified actions with:")
    print("  npx sello actions")
    print()
    print("Or open:")
    print(f"  {result['actionsUrl']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
