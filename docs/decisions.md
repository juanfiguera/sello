# Implementation Decisions

## Initial Scaffold

- Use plain TypeScript modules with Node 24's native type stripping for the first implementation slice.
- Use Node's built-in test runner to avoid dependency installation before the crypto-library spike.
- Keep `package.json` npm-compatible, but run tests with `node --run test` or the raw `node --test --experimental-strip-types` command while `npm` is unavailable in this workspace.
- Start with token-derived identifiers because they require no third-party dependencies and exercise the spec's exact-byte handling rule.

## Deterministic CBOR

- Implement a narrow deterministic CBOR subset locally for early receipt-body and protected-header work.
- Support only the value types currently needed by the protocol: integers, text strings, byte strings, maps, and tag 0 timestamps.
- Reject non-minimal length encodings, indefinite lengths, unsupported major types, and maps whose keys are not in deterministic order.
- Revisit this decision during the library spike before publishing interop vectors; the local helper is intentionally small, not a general-purpose CBOR library.

## Canonical Log URLs

- Treat the trusted log identity as an already-normalized URL string.
- Reject common alternate spellings rather than silently normalizing them: uppercase hostnames, default ports, query strings, fragments, userinfo, dot segments, and non-canonical percent encoding.
- Compare accepted log identities byte-for-byte so the signed `sello_log_url`, the trusted set, and the returning proof log all use the same identifier.

## COSE Protected Header Bytes

- Decode protected headers for validation, but keep the original protected-header byte string attached to the decoded value.
- Later COSE signature verification and HPKE opening must use those original bytes as the signed bytes and AAD, not a reserialized map.

## HPKE Base Mode

- Use Node's built-in X25519, HMAC-SHA256, and ChaCha20-Poly1305 primitives for the first local implementation because this workspace currently lacks npm.
- Keep the HPKE code limited to the single Sello v0.1 suite: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, and ChaCha20-Poly1305 in base mode.
- Pin the helper against RFC 9180 Appendix A.2.1 so implementation mistakes show up as byte-level test failures.
- Revisit this decision before production use; a maintained HPKE library is still preferable if it keeps the protocol surface smaller and auditable.

## COSE_Sign1 And Ed25519

- Implement only the narrow Sello COSE_Sign1 profile locally: protected bstr, empty unprotected map, embedded payload bstr, and Ed25519 signature bstr.
- Build the RFC 9052 `Sig_structure` with context string `Signature1`, the exact protected-header bytes, empty external AAD, and the embedded HPKE payload.
- Use Node's built-in Ed25519 signing and verification with raw-key DER wrapping helpers so fixtures and registries can still use raw 32-byte keys.

## Signed JSON Registry

- Verify the detached signature over the exact UTF-8 JSON bytes before parsing registry entries.
- Store registry `kid` keys as lowercase hex strings and resolve from the protected-header `kid` bytes by hex encoding those bytes.
- Treat revocation as a separate check after lookup: a revoked key is accepted only when the log integrated time is verifiably before `revoked_at`.
- Fail closed when a key is revoked and the log entry lacks verifiable integrated time.

## Mock Transparency Log

- Keep the first log implementation in memory and deterministic enough for tests.
- Index entries by the protected-header `sello_token_ref` and return `completeness: "complete"` because the mock owns the whole entry set.
- Bind the mock proof to the canonical log URL, entry index, integrated time, and exact envelope hash. This is not a Merkle proof, but it exercises the same owner-side data dependencies the Rekor adapter will need.

## Owner Verification Outcomes

- Return verified receipts and rejected receipts separately so one bad log entry does not prevent owners from seeing other valid receipts.
- Use stage-specific rejection codes for log binding, proof, registry, revocation, COSE, HPKE, and body-validation failures.
- Treat exact duplicates as `status: "duplicate"` records pointing at the first valid receipt, not as cryptographic failures.
- Preserve distinct same-second activity and flag it on both affected records.

## Service Receipt Creation Boundary

- `createReceipt` accepts already-verified token claims plus the raw token bytes used for Sello identifier derivation.
- `createReceiptFromJwsToken` is the service-facing helper for v0.1 compact JWS tokens. It verifies the JWS signature before exposing `owner_hpke_pk` or `sello_logs`.
- The token-profile module deliberately does not implement token authorization semantics such as scope or expiry; those remain service policy outside Sello.

## JWS Token Profile

- Support compact-serialized JWS with JSON protected header and JSON payload.
- Require `alg: "EdDSA"` and reject `crit` headers in the first implementation.
- Verify the signature over the exact compact JWS signing input before parsing Sello claims.
- Validate `owner_hpke_pk` as unpadded base64url encoding of a raw 32-byte X25519 public key.
- Validate `sello_logs`, when present, as an array of canonical log URL strings.
- Reject impossible unpadded base64url lengths before relying on Node's decoder behavior.

## Demo Command

- Use `node --run demo` for the first local end-to-end demo because the repository does not yet ship a packaged `sello` binary.
- The demo prints success, error, and denied receipts as verified JSON, and `--tamper` appends a deliberately bad entry to show structured rejection output.
