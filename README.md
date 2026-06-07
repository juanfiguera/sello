![Sello banner](docs/assets/sello-banner.png)

# Sello

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

To see the tiny wrapped-tool source:

```bash
npx --yes sello init-demo
```

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
- A TypeScript reference implementation in [`src/`](src/).
- Implementation-backed v0.1 test vectors in [`fixtures/vectors/sello-v0.1.json`](fixtures/vectors/sello-v0.1.json).
- Security review notes in [`docs/security-review.md`](docs/security-review.md).
- SDK security audit notes in [`docs/sdk-security-audit.md`](docs/sdk-security-audit.md).

The implementation includes a local end-to-end demo, compact JWS token verification, COSE_Sign1 receipt envelopes, HPKE encryption, a mock transparency log, a Rekor discovery adapter, owner verification, an MCP middleware prototype, security review notes, and a local benchmark. Live Rekor proof verification and production identity operations are still future work.

📄 **Paper:** [Notarized Agents: Receiver-Attested Confidential Receipts for AI Agent Actions](https://arxiv.org/abs/2606.04193) (arXiv:2606.04193, submitted June 2026). Local PDF: [docs/paper/notarized-agents.pdf](docs/paper/notarized-agents.pdf).

## Start Here

| Goal | Read |
|------|------|
| Add Sello in a few lines | [SDK Quickstart](docs/sdk-quickstart.md) |
| Emit your first receipt | `npx --yes sello dev`, then `npx --yes sello emit-demo` |
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

Sello works with your own log server. `sello.build` is optional convenience, not a protocol requirement.

To try the repo's local loop:

```bash
# Terminal 1
node --run dev

# Terminal 2
node --run example:tool
node --run actions
```

The example wraps a fake calendar tool, emits a service-signed encrypted receipt, and lets the owner verify it from the local action log.

For an MCP-shaped `tools/call` boundary, run `node --run example:mcp` instead of `node --run example:tool`.

For a smaller production-shaped MCP example, see [examples/mcp-minimal-server.ts](examples/mcp-minimal-server.ts). It wraps one `tools/call` handler with `sello.service()` and leaves unknown tools unreceipted.

## The First 10 Minutes

If you are implementing Sello, start with one local loop:

1. Generate a fixed owner HPKE key pair.
2. Generate a fixed service Ed25519 signing key.
3. Create one mock compact JWS token containing `owner_hpke_pk` and `sello_logs`.
4. Have the service create one receipt for one fake action.
5. Store the receipt in a mock log under `sello_token_ref`.
6. Have the owner fetch, verify, and decrypt the receipt.

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

A Sello-aware service does this for each agent action:

1. Verify the agent's authorization token.
2. Read `owner_hpke_pk` and `sello_logs` from the verified token.
3. Compute `sello_token_ref = SHA-256(raw compact JWS bytes)`.
4. Build a CBOR receipt body describing the action.
5. Encrypt the receipt body to the owner with HPKE.
6. Sign the COSE_Sign1 envelope with the service key.
7. Publish the envelope to an owner-trusted transparency log.

The service signs what it observed. It does not need the owner's private key, and it does not need to understand the owner's downstream audit workflow.

For most services, Sello should fit as middleware around an existing request handler: verify token, run action, emit receipt.

## Owner Verification

An owner verifier does this when reconstructing activity:

1. Compute `sello_token_ref` from the same raw compact JWS bytes.
2. Query every trusted log for matching receipts.
3. Confirm each receipt's `sello_log_url` exactly matches the log that returned the proof.
4. Verify log inclusion.
5. Resolve the service signing key from `kid`.
6. Apply revocation rules using log integrated time.
7. Verify the COSE signature.
8. Decrypt the HPKE payload.
9. Validate and display the receipt body.

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

Issues and pull requests are welcome. This is an early draft; adversarial review is the point.

## License

Apache 2.0. See [LICENSE](LICENSE).
