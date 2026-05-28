# Security Review Notes

Date: 2026-05-28

Scope: implementation-level review of the TypeScript reference implementation's crypto API usage. This is not an external cryptographic audit.

## Summary

The reference implementation keeps the cryptographic surface deliberately small:

- SHA-256 uses Node's `createHash`.
- Ed25519 signing and verification use Node's built-in Ed25519 support.
- X25519 key agreement uses Node's built-in X25519 support through `diffieHellman`.
- HPKE v0.1 support is limited to the single specified suite: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305.
- COSE_Sign1 support is limited to the Sello profile: protected header bytes, empty unprotected map, embedded payload, and Ed25519 signature.
- JWS support is limited to compact JWS with `alg: "EdDSA"` and no `crit` header.

The implementation passes the current end-to-end test suite and pins HPKE behavior against RFC 9180 Appendix A.2.1.

## Findings

No release-blocking issues were found in this pass.

One small hardening change was made during review: base64url decoding now rejects impossible unpadded lengths (`length % 4 === 1`) before handing data to Node's decoder. Tests cover this for JWS token claims and registry signatures.

## Positive Checks

- JWS payload claims are parsed only after signature verification.
- COSE signature verification uses the exact protected-header bytes from the envelope, not a reserialized header map.
- HPKE `aad` is the exact protected-header byte string.
- HPKE `info` binds the Sello suite label, registry-resolved service identifier, and `sello_token_ref`.
- X25519 all-zero shared secrets are rejected.
- Revocation checks use log integrated time, not service-asserted receipt timestamps.
- Log identity is checked by canonical URL equality between the signed header and returning log.
- Decrypted receipt contents are not surfaced for entries that fail before HPKE succeeds.

## Residual Risks

- The HPKE and COSE implementations are intentionally narrow local implementations. They should be replaced with well-maintained libraries or externally audited before production use.
- Rekor support is currently discovery-only. Live Rekor inclusion-proof verification and witnessed-root validation remain future work.
- The mock transparency log proof is not a Merkle proof. It exists to exercise owner-side data flow in tests.
- Key lifecycle operations are not specified beyond registry lookup and revocation checks.
- Token authorization semantics such as expiry, audience, and scope remain service policy outside Sello.
- No constant-time comparison is used for non-secret public values such as token references and log URLs. This is acceptable for the current data model, but should be revisited if secret-bearing comparisons are added.

## Recommended Production Gates

Before production use:

1. Replace or audit the local HPKE implementation.
2. Replace or audit the local COSE_Sign1 implementation.
3. Add live Rekor proof verification against witnessed log roots.
4. Add fuzz/property tests for CBOR decoding, COSE envelope parsing, and JWS parsing.
5. Review key storage, rotation, and revocation operations for the deployment environment.
