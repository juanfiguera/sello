# SDK Security Audit Notes

These notes cover the first Stripe-style SDK implementation pass. They are written for reviewers who need the full plan context: production Rekor proof verification, hosted dashboard key delegation, managed remote signing, and durable on-disk queues remain deferred.

## Phase 0: Contract And Docs

- Service emission and owner viewing are documented as separate environments.
- The service process is not required to hold `SELLO_OWNER_KEY`.
- Hosted `sello.build` is described as optional convenience, not as a protocol dependency.
- Deferred production features are named in `docs/sdk-build-plan.md`.

## Phase 1: Env-First Facade

- `sello.service()` accepts env config, service-id override, or explicit config.
- Missing-config errors are actionable and do not print key material.
- `sello inspect-env` redacts key and secret values.
- Hosted `SELLO_SECRET_KEY` mode fetches config, but local receipt signing remains the default trust model.

## Phase 2: Build/Submit Split

- Receipt cryptography remains unchanged: the same protected headers, HPKE payload, and COSE_Sign1 envelope are produced before append.
- Existing `createReceipt()` behavior is preserved by composing build plus append.
- Background submission is bounded and exposes `flush()`, `onSubmitError`, and `onDrop`.
- Background mode is low-latency, not a strict durability guarantee; `submit.mode: "await"` remains available.

## Phase 3: Tool Wrapper

- Token verification happens before handler execution.
- Invalid tokens prevent the handler from running and emit no receipt.
- Success, error, and denied paths emit receipts without including plaintext request or response bodies.
- The wrapper uses the configured service identity and key for every receipt.

## Phase 4: Logs And Action Viewing

- Local `/actions` and `sello actions` use owner-side verification and HPKE decryption.
- Public log entries remain encrypted.
- Viewing details requires `SELLO_OWNER_KEY` or local dev state created by `sello dev`.
- Production registry URLs require a registry signature and trust root before `sello actions` will use them.

## Phase 5: Docs And First-Run Flow

- The quickstart tool reads ignored local dev state from `.sello/dev.json`; it does not print the service key, owner key, or agent token.
- The example uses `submit: { mode: "await" }` so the command succeeds only after the receipt append completes.
- The example canonicalizes only tool input fields and excludes the authorization token wrapper from the action input hash.
- The MCP-style example reads the bearer token from the transport header, but hashes only the `tools/call` method and params.
- README and quickstart docs keep self-hosting first-class and describe `sello.build` as optional convenience.

## Residual Risks

- Background submission can drop receipts under sustained pressure if the bounded queue fills. This is surfaced through `onDrop`; durable queues are deferred.
- The HTTP log adapter defines a minimal Sello-compatible JSON transport. Production transparency-log proof formats need dedicated adapters.
- JWKS support currently selects the first Ed25519 OKP key. Key selection by token `kid` should be added before relying on multi-key issuers.
- Hosted dashboard decryption is not implemented; any hosted viewer must use client-side decryption or explicit delegated viewer keys.
