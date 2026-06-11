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
  <a href="#add-sello-to-a-tool">Add Sello</a> &middot;
  <a href="#see-logged-actions">Actions</a> &middot;
  <a href="#how-it-works">How It Works</a> &middot;
  <a href="#learn-more">Learn More</a> &middot;
  <a href="SPEC.md">Protocol</a> &middot;
  <a href="https://arxiv.org/abs/2606.04193">Paper</a> &middot;
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

`sello dev` creates local keys, a demo token, a service registry, and a local transparency log under `.sello/`. The log stores encrypted receipt entries, not plaintext action details.

## Add Sello to a Tool

```ts
import { sello } from "sello";

const receipts = sello.service();

export const createEvent = receipts.tool("calendar.create_event", async (request) => {
  return calendar.events.create(request);
});
```

In local dev, `npx sello dev` supplies the config this snippet needs. In production, configure your service with a service id, service signing key, token issuer, and log URL:

```bash
SELLO_SERVICE_ID=calendar.example.com/mcp/v1
SELLO_SERVICE_KEY=sello_live_local_...
SELLO_TOKEN_ISSUER_JWKS=https://auth.example.com/.well-known/jwks.json
SELLO_LOG_URL=https://logs.example.com/api
SELLO_SUBMIT_MODE=background
```

Sello works with your own log server. Using `sello.build` is an optional convenience, not a protocol requirement.

To scaffold a tiny emitter or HTTP route:

```bash
npx --yes sello init-demo
npx --yes sello init-http-demo
```

## See Logged Actions

```bash
npx sello actions
```

In local dev, `sello actions` reads the latest dev token and owner key from `.sello/dev.json`. To inspect actions for a specific agent token, pass it explicitly:

```bash
npx sello actions --token <agent-token>
```

The token is the same authorization token the agent used when it called services. Sello hashes the exact token bytes into `sello_token_ref`, queries trusted logs, verifies matching receipts, and decrypts them with the owner key.

Public logs store encrypted receipts. Viewing action details requires the owner private key or an explicitly delegated viewer key.

## How It Works

Most agent logs are written by the same system whose behavior they describe. If the agent, runtime, or operator is compromised, those logs can be incomplete or false.

Sello moves receipt-writing to the services the agent calls. The service was present for the action, but it is outside the agent's own logging path.

1. The agent calls a service with an authorization token.
2. The service verifies the token, runs the action, and signs an encrypted receipt for what it observed.
3. A transparency log stores the encrypted receipt.
4. The owner later fetches, verifies, and decrypts the receipt.

Sello helps an owner verify that a specific service signed a specific receipt, the receipt was encrypted for the owner, the receipt was included in a trusted transparency log, and the receipt body was not modified after signing.

Sello does not prove that the agent called every service it should have called, that every service is honest, or that unauthenticated log indexes returned complete results. Those limits are intentional and documented in the spec.

## Learn More

- [SDK Quickstart](docs/sdk-quickstart.md): local dev, HTTP demo, self-hosted config, and hosted config.
- [Protocol Walkthrough](docs/protocol-walkthrough.md): the primitive receipt loop for implementers.
- [SPEC.md](SPEC.md): the Sello protocol draft.
- [Notarized Agents paper](https://arxiv.org/abs/2606.04193): design rationale, threat model, and prior art.
- [examples/mcp-minimal-server.ts](examples/mcp-minimal-server.ts): a small MCP-shaped integration.
- [docs/security-review.md](docs/security-review.md) and [docs/sdk-security-audit.md](docs/sdk-security-audit.md): current review notes.

This package is TypeScript today; no Python SDK ships yet. Live Rekor proof verification and production identity operations are still future work.

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
