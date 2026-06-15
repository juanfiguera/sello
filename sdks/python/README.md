# Sello Python SDK

Python support lives in `sdks/python/` so the repository stays easy to scan:

- `sdks/typescript/` contains the TypeScript SDK and reference implementation.
- `sdks/python/src/sello/` contains the Python SDK.

The Python SDK mirrors the TypeScript service-side facade:

```bash
pip install sello
```

```py
import sello

receipts = sello.service()

@receipts.tool("calendar.create_event")
def create_event(request):
    return calendar.events.create(request)
```

The service process emits receipts. It does not need the owner private key.

## Quickstart Example

From the repository root, start the local dev log in one terminal:

```bash
npx --yes sello dev
```

Then run the Python example in another terminal:

```bash
python -m pip install ./sdks/python
python sdks/python/examples/quickstart_tool.py
npx --yes sello actions
```

The example reads `.sello/dev.json`, wraps a mock calendar action with `@receipts.tool(...)`, emits one encrypted receipt, and then lets the Sello CLI verify it locally.

## Local Development

For contributing to the SDK from the repository root:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install ./sdks/python
python -m unittest discover -s sdks/python/tests
```

## Current Scope

The Python SDK currently focuses on service-side receipt emission:

- env-first `sello.service()` config,
- `@receipts.tool(...)` decorator support,
- compact JWS verification,
- HPKE encryption,
- COSE_Sign1 receipt signing,
- memory and HTTP log adapters,
- background submission with `flush()`.

Owner-side viewing is still handled by the Sello CLI and lower-level protocol tooling.
