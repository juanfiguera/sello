# Protocol Walkthrough

This guide is for people implementing Sello itself or studying the receipt flow below the SDK. If you only want to try Sello or add it to a service, start with the README or [`docs/sdk-quickstart.md`](sdk-quickstart.md).

## Goal

Build the smallest complete Sello loop:

1. One mock action happens.
2. The service creates one encrypted signed receipt.
3. A mock transparency log stores it under `sello_token_ref`.
4. The owner fetches, verifies, and decrypts it.

Run the complete loop first:

```bash
node --run demo
```

The runnable source is [`sdks/typescript/src/cli/demo.ts`](../sdks/typescript/src/cli/demo.ts).

## Local Pieces

The primitive loop needs these pieces:

| Piece | Local helper | Why it exists |
|-------|--------------|---------------|
| Owner key | `generateHpkeKeyPair()` | The public key goes in the token. The private key decrypts receipts later. |
| Service key | `generateEd25519KeyPair()` | The service signs receipts for actions it observed. |
| Token issuer key | `generateEd25519KeyPair()` | The issuer signs the mock agent token. |
| Transparency log | `new MockTransparencyLog(...)` | The log stores encrypted signed receipts by `sello_token_ref`. |
| Service registry | `loadSignedRegistry(...)` | The owner uses it to resolve service public keys and revocation status. |

Start with the owner key:

```ts
import { base64urlEncode, generateHpkeKeyPair } from "sello";

const owner = generateHpkeKeyPair();
const ownerHpkePk = base64urlEncode(owner.publicKey);
```

Put `ownerHpkePk` in the token's `owner_hpke_pk` claim. Keep `owner.privateKey` for the owner verifier.

Then create the other local pieces:

```ts
import { generateEd25519KeyPair, MockTransparencyLog } from "sello";

const service = generateEd25519KeyPair();
const tokenIssuer = generateEd25519KeyPair();
const trustRoot = generateEd25519KeyPair();
const log = new MockTransparencyLog("https://rekor.example.com/api");
```

## Flow

1. Sign a compact JWS token with `signSelloJwsToken(...)`.
2. Include `owner_hpke_pk` and `sello_logs` in the signed token.
3. Create a receipt with `createReceiptFromJwsToken(...)`.
4. Verify with `verifyReceipts(...)` using the same raw token, owner private key, mock log, and service registry.

You know the loop works when the owner can print one verified receipt:

```json
{
  "service": "example.com/tool/v1",
  "action-type": "tools/call",
  "result-status": "success",
  "verified": true
}
```

Do not start with Rekor, MCP middleware, distributed identity, or CLI polish. Those become much easier once one local receipt works end to end.
