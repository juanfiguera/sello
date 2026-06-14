# Sello Python SDK

Python support lives in `python/` so the repository stays easy to scan:

- `src/` contains the TypeScript reference implementation.
- `python/src/sello/` contains the Python SDK.

The Python SDK mirrors the TypeScript service-side facade:

```py
import sello

receipts = sello.service()

@receipts.tool("calendar.create_event")
def create_event(request):
    return calendar.events.create(request)
```

The service process emits receipts. It does not need the owner private key.

## Local Development

From the repository root:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install ./python
python -m unittest discover -s python/tests
```

## Current Scope

This first Python SDK pass focuses on service-side receipt emission:

- env-first `sello.service()` config,
- `@receipts.tool(...)` decorator support,
- compact JWS verification,
- HPKE encryption,
- COSE_Sign1 receipt signing,
- memory and HTTP log adapters,
- background submission with `flush()`.

Owner-side viewing is still handled by the Sello CLI and lower-level protocol tooling.
