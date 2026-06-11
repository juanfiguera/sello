![Sello banner](docs/assets/sello-banner.png)

<h1 align="center">Sello</h1>

<p align="center">
  <a href="https://github.com/juanfiguera/sello/actions/workflows/ci.yml"><img alt="build status" src="https://img.shields.io/github/actions/workflow/status/juanfiguera/sello/ci.yml?branch=main&style=flat-square&label=build&labelColor=0b1011&color=e8f7ef"></a>
  <a href="https://www.npmjs.com/package/sello"><img alt="npm version" src="https://img.shields.io/npm/v/sello?style=flat-square&label=npm&labelColor=0b1011&color=e8f7ef"></a>
  <a href="https://www.npmjs.com/package/sello"><img alt="npm downloads" src="https://img.shields.io/npm/dm/sello?style=flat-square&label=downloads&labelColor=0b1011&color=e8f7ef"></a>
  <a href="LICENSE"><img alt="license Apache-2.0" src="https://img.shields.io/npm/l/sello?style=flat-square&label=license&labelColor=0b1011&color=e8f7ef"></a>
  <a href="package.json"><img alt="Node.js 22.7 or newer" src="https://img.shields.io/badge/node-%3E%3D22.7-e8f7ef?style=flat-square&labelColor=0b1011"></a>
  <a href="https://arxiv.org/abs/2606.04193"><img alt="arXiv 2606.04193" src="https://img.shields.io/badge/arXiv-2606.04193-e8f7ef?style=flat-square&labelColor=0b1011"></a>
</p>

<p align="center">
  <a href="#try-it">Quickstart</a> &middot;
  <a href="#what-sello-gives-you">What It Does</a> &middot;
  <a href="#add-sello-in-a-few-lines">SDK</a> &middot;
  <a href="SPEC.md">Protocol</a> &middot;
  <a href="https://arxiv.org/abs/2606.04193">Paper</a> &middot;
  <a href="#repository-status">Status</a> &middot;
  <a href="#sharp-edges">Sharp Edges</a> &middot;
  <a href="#related-work">Prior Art</a> &middot;
  <a href="SECURITY.md">Security</a> &middot;
  <a href="CONTRIBUTING.md">Contributing</a> &middot;
  <a href="#license">License</a>
</p>

Sello is a protocol for independently-verifiable records of AI agent actions.

**Pronunciation:** commonly `SEH-yoh` or `SEH-yo`, from the Spanish word *sello*, meaning a seal or stamp.

When an agent calls a service, the service creates a receipt for what it observed. The receipt is encrypted to the agent owner, signed by the service, and published to a transparency log. Later, the owner can retrieve and verify that receipt without trusting the agent's own logs.

```text
agent calls service
  -> service creates encrypted signed receipt
  -> transparency log stores receipt
  -> owner fetches, verifies, decrypts
```

## Try It

Requires Node.js 22.7 or newer.

From a new project or temporary folder:

```bash
# Terminal 1
npx --yes sello dev

# Terminal 2
npx --yes sello emit-demo
npx --yes sello actions
```

Then open:

```text
http://localhost:8787/actions
```

## What Just Happened?

`sello dev` created a local owner key, service key, token, registry, and transparency log. `sello emit-demo` called a small demo tool with that token. The service verified the token, ran the tool function, signed an encrypted receipt for the action it observed, and stored that encrypted receipt in the local log. `sello actions` fetched the receipt, verified the log entry and service signature, decrypted it with the owner key, and printed the owner's view.

Local dev state lives under `.sello/`. The dev log is stored as encrypted receipt entries in `.sello/dev-log.jsonl`, so receipts survive restarting `sello dev` while staying out of git.

## Why Sello?

Most agent logs are written by the same system whose behavior they describe. If the agent, runtime, or operator is compromised, those logs can be incomplete or false.

Sello moves receipt-writing to the services the agent calls. The service was present for the action, but it is outside the agent's own logging path. The architectural inversion is simple: the signer is not the agent or its operator, but the receiver that observed the action.

## What Sello Gives You

Sello helps an owner verify that:

- A specific service signed a specific receipt.
- The receipt was encrypted for the owner.
- The receipt was included in a trusted transparency log.
- The receipt body was not modified after signing.

Sello does not prove that the agent called every service it should have called, that every service is honest, or that unauthenticated log indexes returned complete results. Those limits are intentional and documented in the spec.

## Repository Status

This repository currently contains:

- [SPEC.md](SPEC.md): the Sello protocol draft.
- A TypeScript reference implementation and SDK facade in [`src/`](src/).
- Implementation-backed v0.1 test vectors in [`fixtures/vectors/sello-v0.1.json`](fixtures/vectors/sello-v0.1.json).
- Security review notes in [`docs/security-review.md`](docs/security-review.md).
- SDK security audit notes in [`docs/sdk-security-audit.md`](docs/sdk-security-audit.md).

The implementation includes a local end-to-end demo, compact JWS token verification, COSE_Sign1 receipt envelopes, HPKE encryption, a mock transparency log, a Rekor discovery adapter, owner verification, an MCP middleware prototype, security review notes, and a local benchmark. The package is TypeScript today; no Python SDK ships yet. Live Rekor proof verification and production identity operations are still future work.

📄 **Paper:** [Notarized Agents: Receiver-Attested Confidential Receipts for AI Agent Actions](https://arxiv.org/abs/2606.04193) (arXiv:2606.04193, submitted June 2026). Local PDF: [docs/paper/notarized-agents.pdf](docs/paper/notarized-agents.pdf).

## Start Here

| Goal | Read |
|------|------|
| Add Sello in a few lines | [SDK Quickstart](docs/sdk-quickstart.md) |
| Emit your first receipt | `npx --yes sello dev`, then `npx --yes sello emit-demo` |
| Wrap one HTTP route | `npx --yes sello init-http-demo`, then `npx --yes sello call-http-demo` |
| Try a wrapped tool locally | `node --run dev`, then `node --run example:tool` |
| Try an MCP-style tool call | `node --run dev`, then `node --run example:mcp` |
| See a minimal MCP integration | [examples/mcp-minimal-server.ts](examples/mcp-minimal-server.ts) |
| Understand the protocol | [SPEC.md](SPEC.md) Quick Start |
| Run the local demo | `node --run demo` |
| Run the test suite | `node --run test` |
| Measure local size/performance | `node --run bench -- --json` |
| Emit receipts from a service | [SPEC.md](SPEC.md) §§3.1, 4.1, 5, 6.2 |
| Verify receipts as an owner | [SPEC.md](SPEC.md) §§4.2, 5, 6.2, 7.1 |
| Build the reference implementation | Start with "The First 10 Minutes" below |

## Add Sello in a Few Lines

```ts
import { sello } from "sello";

const receipts = sello.service();

export const createEvent = receipts.tool("calendar.create_event", async (request) => {
  return calendar.events.create(request);
});
```

Then inspect verified actions:

```bash
npx sello actions --token <agent-token>
```

In local dev, `sello dev` prints and saves a demo token:

```bash
SELLO_ACTION_TOKEN=eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...
```

You usually do not need to copy it. `npx sello actions` reads the latest dev token from `.sello/dev.json`. Use `--token` when you want to inspect receipts for a specific agent authorization token from your own system.

Sello works with your own log server. Using `sello.build` is an optional convenience, not a protocol requirement.

To try the repo's local loop:

```bash
# Terminal 1
node --run dev

# Terminal 2
node --run example:tool
node --run actions
```

The example wraps a mock calendar tool, emits a service-signed encrypted receipt, and lets the owner verify it from the local action log.

For an MCP-shaped `tools/call` boundary, run `node --run example:mcp` instead of `node --run example:tool`.

For a smaller production-shaped MCP example, see [examples/mcp-minimal-server.ts](examples/mcp-minimal-server.ts). It wraps one `tools/call` function with `sello.service()` and leaves unknown tools unreceipted.

For an installed-project bridge from demo to app, run `npx sello init-http-demo`. It writes a small dependency-free HTTP route that imports `sello`, reads the local dev config, verifies a bearer token, runs the route function, and emits a receipt. With the local log and route running, `npx sello call-http-demo` sends the demo request for you.

## The First 10 Minutes

The first milestone is not a production log or a full MCP server. It is one mock action that produces one encrypted receipt and one verified owner view.

Run the complete local loop first:

```bash
node --run demo
```

Then build the same loop yourself with these local pieces:

| Piece | Local helper | Why it exists |
|-------|--------------|---------------|
| Owner key | `generateHpkeKeyPair()` | The public key goes in the token. The private key decrypts receipts later. |
| Service key | `generateEd25519KeyPair()` | The service signs receipts for actions it observed. |
| Token issuer key | `generateEd25519KeyPair()` | The issuer signs the mock agent token. |
| Transparency log | `new MockTransparencyLog(...)` | The log stores encrypted signed receipts by `sello_token_ref`. |
| Service registry | `loadSignedRegistry(...)` | The owner uses it to resolve the service public key and revocation status. |

That setup starts like this:

```ts
import { generateEd25519KeyPair, generateHpkeKeyPair, MockTransparencyLog } from "sello";

const owner = generateHpkeKeyPair();
const service = generateEd25519KeyPair();
const tokenIssuer = generateEd25519KeyPair();
const trustRoot = generateEd25519KeyPair();
const log = new MockTransparencyLog("https://rekor.example.com/api");
```

Next, sign a compact JWS token with `signSelloJwsToken(...)`. Put the owner's HPKE public key in `owner_hpke_pk` and the log URL in `sello_logs`. Pass that token to `createReceiptFromJwsToken(...)` with one mock action input and output. Finally, call `verifyReceipts(...)` with the same raw token, the owner private key, the mock log, and the service registry.

For a compact runnable version, read [`src/cli/demo.ts`](src/cli/demo.ts). It is the smallest end-to-end implementation in the repo.

Do not start with Rekor, MCP middleware, distributed identity, or CLI polish. Those become much easier once one local receipt works end to end.

You know the first loop works when the owner can print one verified receipt:

```json
{
  "service": "example.com/tool/v1",
  "action-type": "tools/call",
  "result-status": "success",
  "verified": true
}
```

## Service Integration

In a real service, Sello belongs at the boundary where an agent request becomes a tool or API action. The wrapper should receive the request, verify the agent token, run your existing function, and emit a receipt without changing the function's return value.

The small version is:

```ts
import { sello } from "sello";

const receipts = sello.service();

export const createEvent = receipts.tool("calendar.create_event", async (request) => {
  return calendar.events.create(request);
});
```

`sello.service()` reads service-side config from the environment. A self-hosted service usually needs:

```bash
SELLO_SERVICE_ID=calendar.example.com/mcp/v1
SELLO_SERVICE_KEY=sello_live_local_...
SELLO_TOKEN_ISSUER_JWKS=https://auth.example.com/.well-known/jwks.json
SELLO_LOG_URL=https://logs.example.com/api
SELLO_SUBMIT_MODE=background
```

For each wrapped action, Sello does the receipt work around your code:

- Before the action, it verifies the agent token and reads `owner_hpke_pk` and `sello_logs`.
- While running the action, it hashes canonical input and output bytes instead of putting plaintext details in the public log.
- After the action, it builds the receipt, encrypts it to the owner, signs it with the service key, and submits it to an owner-trusted log.

The service signs what it observed. It does not need the owner's private key, and it does not need to understand the owner's downstream audit workflow.

If you cannot use `receipts.tool(...)`, mirror the same sequence manually with `createReceiptFromJwsToken(...)`: verify token, run action, hash inputs and outputs, create receipt, submit to the log.

## Owner Verification

The owner side starts with the same raw agent token and the owner's private key. In local dev, `sello dev` saves both under `.sello/`, so the short command works:

```bash
npx sello actions
```

Outside local dev, pass the token you want to inspect:

```bash
npx sello actions --token <agent-token>
```

The verifier needs four inputs:

| Input | Where it comes from | What Sello uses it for |
|-------|---------------------|------------------------|
| Raw agent token | Your auth system or local dev state | Computes `sello_token_ref` and reads trusted logs. |
| Owner private key | Owner-controlled config | Decrypts receipts after all public checks pass. |
| Service registry | Signed registry or local dev state | Resolves service signing keys and revocation status. |
| Trusted logs | Token claims plus owner policy | Finds receipts and verifies inclusion. |

For each candidate receipt, Sello checks that the returning log matches the signed `sello_log_url`, verifies log inclusion, resolves the service key, applies revocation using log integrated time, verifies the COSE signature, decrypts the HPKE payload, and validates the receipt body.

For most owners, Sello should fit as a pull-based audit tool: provide the token and owner key, then retrieve the verified trail from trusted logs.

## Core Terms

- **Owner:** deploys the agent and holds the HPKE private key.
- **Agent:** calls services with authorization tokens.
- **Service:** signs receipts for actions it observed.
- **Receipt:** encrypted CBOR body inside a signed COSE_Sign1 envelope.
- **Transparency log:** append-only store that returns inclusion proofs.
- **`sello_token_ref`:** SHA-256 of the exact raw compact JWS bytes.
- **`sello_log_url`:** canonical URL of the log that stored the receipt.

## Related Work

Verifiable records of agent activity are an active area, and several projects are working nearby. Sello's specific combination, where the receiving service signs the receipt, encrypts it to the owner, and publishes it to a public transparency log, appears to be distinct, but the surrounding space is rich and worth knowing.

Closest neighbors include Signet, which co-signs MCP responses but keeps receipts in operator-controlled storage; AgentROA, which publishes per-action receipts to a SCITT log but signs at an operator-side gateway and in cleartext; Agent Receipts, which signs on the agent-platform side; and the IETF SCITT working group, whose COSE_Sign1 transparency-receipt framework Sello builds on. Each gets one or two of Sello's four properties. None, as far as we found, combines all four.

Much of this prior work surfaced after Sello's design had already converged on similar primitives. That independent convergence is a good sign the problem is real. See [SPEC.md](SPEC.md) §12 for the fuller prior-art discussion.

## Sharp Edges

- Hash the exact raw compact JWS bytes. Do not parse and reserialize first.
- Compare log identities by canonical URL string; see `SPEC.md` §6.2.
- Do not treat an unauthenticated Rekor/off-log index as proof of completeness.
- Use verifiable log integrated time for revocation decisions, not the receipt timestamp.
- Deduplicate only on the full spec key, including action type and input/output hashes.

## Feedback

Issues and pull requests are welcome. This is an early draft; adversarial review is the point. See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution notes and [SECURITY.md](SECURITY.md) for sensitive reports.

## License

Apache 2.0. See [LICENSE](LICENSE).
