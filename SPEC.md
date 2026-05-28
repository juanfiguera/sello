# Sello Protocol

**Etymology:** *Sello* is the Spanish word for a seal or stamp: both the device that produces an authoritative imprint and the imprint itself. In classical use a seal served two purposes at once. It hid the contents of a document by sealing it shut, and it identified who had been present to seal it through the unique impression of the sealer's mark. The protocol described in this document applies the same dual principle to AI agent actions: each receipt is sealed (HPKE-encrypted to the agent owner) and stamped (cryptographically signed by the receiving service) before being published to a public transparency log.

**Version:** 0.1.0-draft
**Status:** Working draft, open for community input
**License:** Apache 2.0
**Reference implementation:** TypeScript implementation included in this repository

---

## Abstract

Sello is a protocol for producing independently-verifiable records of AI agent actions. When an agent calls a service, the service signs a receipt of what it observed, encrypts the receipt to the agent owner's public key, and publishes the encrypted receipt to a public transparency log. The owner queries trusted logs later and reconstructs a tamper-evident trail of retrieved agent activity, attested by independent third parties rather than by the agent itself. Completeness of that trail depends on the authenticated query or audit mechanisms described in §6.1.

This document specifies the receipt envelope format, the cryptographic primitives, the transparency log integration, and the owner-side retrieval flow. Several discovery, key-management, and identity-binding mechanisms are out of scope for v0.1 and are flagged in §9.

## Quick Start (Non-Normative)

This section is a practical orientation for implementers. The normative protocol begins in §1.

Sello has three jobs:

1. A **service** writes a receipt for an agent action it observed.
2. The service encrypts that receipt so only the **owner** can read it.
3. The service publishes the encrypted, signed receipt to a **transparency log** so the owner can retrieve and verify it later.

If you are reading this document for the first time:

| Goal | Read |
|------|------|
| Understand the security model | §2 and §8 |
| Emit receipts from a service | §3.1, §4.1, §5, and §6.2 |
| Verify receipts as an owner | §4.2, §5, §6.2, and §7.1 |
| Implement the wire format | §5 and Appendix B |
| Review known limitations | §6.1, §8.3, and §13 |

The smallest useful implementation is local and does not need Rekor, MCP middleware, or production identity infrastructure. Start with a mock log and fixed test keys:

```text
owner key pair
  -> authorization token carries owner_hpke_pk and sello_logs
agent calls service with token
service verifies token, creates receipt, encrypts it, signs it
mock log stores receipt under sello_token_ref
owner queries mock log, verifies receipt, decrypts receipt body
```

One receipt has this shape:

```text
COSE_Sign1 envelope
  protected header:
    kid
    sello_version
    sello_token_ref
    sello_log_url
  payload:
    HPKE enc || ciphertext
      decrypted plaintext:
        CBOR receipt body
          agent-identifier
          action-type
          action-input-hash
          action-output-hash
          result-status
          timestamp
```

At a high level, an owner accepts a receipt only when:

- The receipt was returned by the same trusted log named in `sello_log_url`.
- The log inclusion proof verifies.
- The service `kid` resolves to a valid, non-revoked signing key.
- The COSE_Sign1 signature verifies.
- HPKE decryption succeeds using the owner's private key.
- The decrypted CBOR receipt body matches §5.3.

### Service Checklist

To emit one v0.1 receipt, a service needs:

- A compact JWS authorization token containing `owner_hpke_pk`.
- A trusted log URL from the token's `sello_logs` claim, or a locally configured owner-trusted log.
- An Ed25519 signing key with a `kid` that owners can resolve through §7.
- The action input, action output, result status, and completion timestamp.

The service then performs the §4.1 flow: hash the raw token bytes to compute `sello_token_ref`, build the receipt body, HPKE-encrypt it to `owner_hpke_pk`, sign the COSE_Sign1 envelope, and submit it to the selected log.

### Owner Checklist

To verify one v0.1 receipt, an owner needs:

- The same raw compact JWS token bytes used by the service.
- The owner's HPKE private key.
- The trusted log set for that token.
- The service identity registry needed to resolve `kid`.
- The log entry, inclusion proof, and integrated time when available.

The owner then performs the §4.2 flow: query every trusted log by `sello_token_ref`, reject receipts whose `sello_log_url` does not exactly match the returning trusted log, verify log inclusion, resolve and check the service key, verify the COSE signature, decrypt the HPKE payload, and validate the receipt body.

### What To Build First

For a reference implementation, build in this order:

1. Token hash and `agent-identifier` derivation.
2. Receipt-body CBOR encoding and validation.
3. Canonical log URL validation (§6.2).
4. HPKE seal/open using fixed keys.
5. COSE_Sign1 sign/verify.
6. A mock transparency log that returns entries by `sello_token_ref`.
7. One end-to-end demo that emits and verifies a receipt.

Appendix B contains implementation-backed vectors generated by the reference implementation. Implementations SHOULD use those vectors as the first interop target before testing against live logs or remote services.

## 1. Problem Statement

Current AI agent observability is structurally compromised: the entity producing the activity log is the same entity whose activity is being logged. A compromised, buggy, or adversarial agent can fabricate, omit, or alter its own traces, and the operator running the agent has no independent way to detect or prove tampering.

Sello addresses this by relocating the receipt-writing function from the agent (or its operator) to the services the agent interacts with. Each service that receives an agent call signs a record of what it observed, using its own cryptographic key, and publishes that record to shared public infrastructure.

The architectural pattern is borrowed from established systems:

- Mesopotamian commercial contracts (circa 3000 BCE) were witnessed by named third parties whose seals were impressed in clay.
- Notarized documents are signed by notaries, not signatories.
- AirTag location reports are submitted by independent iPhones, not by the AirTag.

In each case, the receipt-writer is a party who was present at the event but is independent of the principal. Sello ports this pattern to AI agent actions.

### 1.1 Use Cases

The following personas illustrate who Sello is intended for and which properties matter to each. They are not normative; they motivate the design choices in §2.

**Enterprise compliance team.** An organization deploys agents that touch regulated systems (financial trade execution, PHI lookups, KYC verification). They need cryptographically-defensible evidence that the agent performed exactly the actions claimed, attested by the regulated systems themselves rather than by the agent's self-report. Their threat model is internal misuse or external compromise of the agent producing falsified audit trails; **P1 (receiver-side signing)** and the integrity-of-recorded-actions property in §8.2 are the load-bearing guarantees. They will typically pair Sello receipts with their existing SIEM and dispute-resolution workflows.

**AI safety research team.** A lab runs long-horizon agents (multi-day, multi-tool, possibly across many providers). They need an independent record of what the agent actually did across services to study capability emergence, tool-use patterns, and possible misuse, without trusting the agent's own logs. Their threat model is the agent itself being the adversary (deceptive or buggy); **P1**, **P3 (transparency log)**, and the independence-of-attestation property in §8.2 are what they're buying. The suppression attack (§8.3) is a known limitation they must address with orthogonal techniques.

**Self-hosting power user.** An individual runs personal agents over calendar, email, and shopping integrations on hosted model-provider infrastructure. They want to answer "what did my agent actually do this morning?" without trusting either the agent or the operator running its inference. Their threat model is the operator silently rewriting traces, and an adversarial agent omitting embarrassing or compromising actions; **P2 (encryption to owner)** and **P4 (owner-side discovery)** matter because they keep the operator out of the receipt-reading loop entirely.

**Regulated-industry SaaS vendor.** A healthcare-data API or financial-data API offers an MCP server. They need to issue receipts proving they were called with a specific scope so their own legal team and downstream auditors can establish exactly what the agent saw and acted on. Their threat model is later dispute ("you exfiltrated PHI you weren't authorized to see") where they must produce contemporaneous evidence; **P1** plus the tamper-evidence property in §8.2 are exactly the regulatory primitive they need. Sello's transparency-log substrate also gives them a way to demonstrate non-repudiation to third parties without standing up bespoke audit infrastructure.

## 2. Design Properties

Sello is defined by four cryptographic properties that, taken together, distinguish it from existing agent observability and audit systems:

**P1. Receiver-side signing.** The signing key is held by the service receiving the agent's call, not by the agent, not by the operator, not by a gateway in the operator's infrastructure.

**P2. Encryption to owner.** Receipt contents are asymmetrically encrypted to the agent owner's public key, allowing the receipt to be safely published on shared public infrastructure without leaking content.

**P3. Public transparency log.** Receipts are appended to a public append-only Merkle log with witness cosigning, providing tamper-evidence for logged receipts and global verifiability of inclusion (see §6.1 for the completeness-of-retrieval caveat).

**P4. Owner-side discovery and decryption.** The agent owner queries the log by authorization token reference, decrypts receipts locally with their private key, and verifies signatures against a registry of service identities.

Implementations claiming Sello compliance MUST satisfy all four properties.

### 2.1 Conformance requirements

A compliant Sello **service** implementation MUST:

- Hold its own Ed25519 signing key, not shared with the owner, the operator, or any gateway in the operator's trust boundary.
- Publish its `kid` → service-identifier → public key mapping through a mechanism conformant with §7, such that owner implementations can resolve `kid` to a public key.
- For the v0.1 JWS token profile (§3.1), verify the authorization token signature before extracting Sello claims.
- Encrypt each receipt payload to the owner's HPKE public key using the suite specified in §5.2.
- Sign the encrypted envelope using COSE_Sign1 with the parameters specified in §5.1.
- Submit each signed envelope to a transparency log per §6.2, including the `sello_logs` constraints for the JWS profile.
- Apply the canonicalization rules specified in §5.3 when computing `action-input-hash` and `action-output-hash`.

A compliant Sello **owner** implementation MUST:

- Hold an HPKE key pair whose public key is bound to the authorization token by the v0.1 JWS token profile (§3.1), or by an equivalent token profile specified in a future Sello version.
- Verify the log inclusion proof against a witness-cosigned Merkle root.
- Resolve the signing service via the identity registry (§7) using the protected header `kid`, obtaining the service public key and the canonical service-identifier.
- Verify the COSE_Sign1 signature against the resolved service public key.
- Reconstruct the HPKE info from the registry-resolved service-identifier and the protected header `sello_token_ref` before attempting HPKE decryption (§5.2).
- Reject any receipt for which inclusion-proof verification, signature verification, or HPKE decryption fails.
- Reject any receipt whose `kid` appears in the registry's `revoked` table per §7.1, applying the integrated-time bound where the log provides one and the fail-closed rule where it does not.
- Reject any receipt whose `sello_log_url` is not byte-for-byte equal to the returning log's canonical URL, or whose returning log's canonical URL is not present in the owner's trusted log set established per §6.2, even if cryptographic verification would otherwise succeed.
- De-duplicate receipts only when they share `kid`, `sello_token_ref`, `timestamp` truncated to whole seconds, `action-type`, `action-input-hash`, and `action-output-hash`, treating them as a single logical event (§8.3).

A compliant Sello **log** implementation MUST:

- Provide append-only storage with Merkle-tree commitment.
- Be cosigned by independent witnesses, such that any inclusion proof can be verified against a witness-cosigned Merkle root (see §6 for rationale).
- Return inclusion proofs alongside retrieved entries.
- Support retrieval by `sello_token_ref` (see §6 for query mechanism). A log or paired index that claims complete query results MUST provide an authenticated completeness mechanism; otherwise retrieval is a discovery aid only (§6.1).

## 3. Actors

**Owner.** The principal who deployed the agent. Holds a long-term HPKE key pair. In the v0.1 JWS token profile (§3.1), the owner's public key is bound to authorization tokens through the token issuer's JWS signature. Other token formats need their own Sello profiles in future versions.

**Agent.** The autonomous software acting on the owner's behalf. The agent presents authorization tokens when calling services. The agent is not a party to the receipt protocol and does not hold signing or encryption keys related to receipts.

**Service.** Any endpoint the agent calls: MCP server, API, tool, A2A (agent-to-agent) peer. The service holds its own long-term signing key, independent of the owner and the operator.

**Log.** A public append-only transparency log supporting Merkle inclusion proofs and witness cosigning. Sello is log-agnostic; see §6 for log requirements and §6.1 for the Sigstore Rekor profile used by v0.1 reference implementations.

### 3.1 v0.1 JWS Token Profile

v0.1 conformance is defined for a JWS-based token profile. In this profile, the owner's HPKE public key is carried as a claim inside the authorization token presented by the agent. The token format MUST be a compact-serialized JWS (RFC 7515) whose payload is constrained, for the purpose of this profile, to a UTF-8-encoded JSON object (RFC 8259). RFC 7515 permits arbitrary octet payloads; this profile narrows the payload to JSON so the `owner_hpke_pk` and `sello_logs` claims can be located by name. The token therefore takes the shape of a JWT (RFC 7519), and a JWT compact serialization satisfies this requirement, but Sello does not require any JWT-specific claim semantics beyond what is stated here. The JSON object MUST contain the claim `owner_hpke_pk`, a string holding the base64url encoding (without padding, per RFC 7515 §2) of the raw 32-byte X25519 public key. The encoded value is exactly 43 characters. The JSON object MAY contain the claim `sello_logs`, a JSON array of canonical log URL strings identifying the owner's trusted transparency logs; canonicalization, normative use, and the absent/empty fallback are defined in §6.2.

When the service receives a request, it MUST verify the JWS signature against the issuing authority's public key before reading any claim. The mechanism by which a service learns the issuer's verification key is out of scope for this version (see §9). After signature verification, the service extracts `owner_hpke_pk`, base64url-decodes it, and uses the resulting X25519 point as the HPKE recipient key in §5.2. The verified JWS cryptographically binds the owner pubkey to the token: an attacker who substitutes a different pubkey invalidates the JWS, and an attacker who reuses a captured token cannot change the recipient.

Other claims in the JWS payload (subject, issuer, scope, expiry) are opaque to Sello. Token authorization semantics remain out of scope per §9. Sello consumes the JWS only to extract `owner_hpke_pk`, obtain the trusted log set from `sello_logs` when present (§6.2), and derive `sello_token_ref` and `agent-identifier`.

This profile couples v0.1 conformance to JWS-based tokens. Other token formats (UCAN, biscuits, macaroons) carry public keys and trusted-log sets through different mechanisms and would require their own §3.1-style profiles in future spec revisions. Implementations that use a non-JWS token format can experiment with Sello's receipt envelope, but they are not conformant with the v0.1 profile until that token format has a specified Sello profile. v0.1 picks JWS because it is the format the MCP authorization spec and most current agent-deployment platforms already emit.

## 4. Protocol Flow

### 4.1 Receipt generation (per-call)

When an agent calls a service:

1. The service receives the call and verifies the authorization token by mechanisms outside the scope of this spec.
2. The service performs the requested action.
3. The service constructs a receipt payload (see §5) describing the action.
4. The service encrypts the payload to the owner's public key using HPKE (RFC 9180). The owner's public key is obtained by the mechanism specified in §3.1 for the JWS token profile; alternative token formats would carry the key through their own §3.1-style profile (see §9).
5. The service signs the encrypted envelope using COSE_Sign1 (RFC 9052) with its Ed25519 private key.
6. The service submits the signed envelope to a transparency log trusted by the owner per §6.2. For the v0.1 JWS token profile, this means a log listed in the token's `sello_logs` claim when present; if the claim is absent or empty, the service falls back to local policy per §6.2.
7. The log returns an inclusion proof and the signed log root.
8. The service MAY return the inclusion proof to the agent for forwarding to the owner; receipt retrieval does not depend on this. Returning the proof inline lets the owner verify a specific receipt without waiting for log indexing (which can lag submission by seconds to minutes on heavily-loaded logs) and without performing a separate log query for that entry. The owner-side flow in §4.2 remains the canonical retrieval path.

### 4.2 Receipt retrieval (owner-side)

When the owner wishes to reconstruct an agent's activity:

1. The owner computes `sello_token_ref = SHA-256(authorization-token-bytes)` over the raw bytes of the JWS compact serialization (§3.1), then queries every log in the trusted set established per §6.2 for entries whose protected header carries that value.
2. Each queried log returns matching encrypted envelopes with inclusion proofs.
3. For each envelope, the owner verifies that its protected-header `sello_log_url` is byte-for-byte equal to the canonical log URL of the log that returned the envelope and inclusion proof, and that this canonical URL is present in the trusted log set established per §6.2; reject the envelope if either check fails. This binds the signed envelope to the log whose proof and integrated time the owner is about to rely on.
4. For each remaining envelope, the owner verifies the log inclusion proof against the witnessed Merkle root.
5. The owner resolves the signing service via the identity registry (§7) using the `kid` from the protected header, obtaining the service public key and the canonical service-identifier. If the `kid` appears in the registry's `revoked` table per §7.1, the owner rejects the receipt unless its log integrated time is strictly before `revoked_at`; receipts on logs that cannot provide a verifiable integrated time are rejected outright when the `kid` is revoked.
6. The owner verifies the COSE_Sign1 signature against the resolved service public key.
7. The owner reconstructs the HPKE info per §5.2 from the registry-resolved service-identifier and the `sello_token_ref` from the protected header.
8. The owner decrypts the HPKE payload using their private HPKE key, with the protected header bytes as `aad`.
9. The owner CBOR-decodes the plaintext into a receipt body and inspects it.

A receipt is considered valid only if all of the following succeed: the receipt's `sello_log_url` is byte-for-byte equal to the returning log's canonical URL and that URL is in the owner's trusted log set (step 3, §6.2), inclusion-proof verification (step 4), registry resolution with the `kid` either absent from `revoked` or with the returning log's integrated time strictly before `revoked_at` (step 5), COSE_Sign1 signature verification (step 6), and HPKE decryption (step 8). The log-binding and trust-set checks are placed before inclusion-proof verification because they are cheaper (no crypto, no registry lookup) and can short-circuit envelopes that the owner would reject regardless of cryptographic validity.

## 5. Receipt Format

The canonical wire format is CBOR-encoded COSE_Sign1. A human-readable JSON debug rendering is also specified for inspection and logging.

### 5.1 Outer envelope (COSE_Sign1)

```
COSE_Sign1 = [
  protected_header: bstr,    // CBOR-encoded header parameters
  unprotected_header: map,   // MUST be empty in v0.1
  payload: bstr,             // HPKE enc || ciphertext (§5.2)
  signature: bstr            // Ed25519 signature
]
```

The unprotected header map MUST be empty in v0.1. Services MUST emit `{}` as the unprotected header, and owners MUST reject envelopes whose unprotected header is non-empty. All Sello-defined envelope metadata is carried either in the protected header or inside the encrypted receipt body; allowing unsigned envelope metadata would create needless interop and security ambiguity.

Protected header parameters:

| Label | Name | Value |
|-------|------|-------|
| 1 | alg | -8 (EdDSA / Ed25519) |
| 2 | crit | OPTIONAL; if present, a non-empty array of labels per RFC 9052 §3.1 (see note below) |
| 4 | kid | non-empty bstr (service key identifier) |
| -65537 | sello_version | "0.1.0" |
| -65538 | sello_token_ref | 32-byte bstr (SHA-256 hash of authorization token; the underlying token MUST contain at least 128 bits of unpredictable entropy, see §8.3) |
| -65539 | sello_log_url | tstr (canonical transparency log base URL; see §6.2) |

A service MAY include the COSE `crit` parameter (label 2) listing any protected header labels whose unrecognized presence by the verifier MUST cause receipt rejection. The `crit` parameter governs forward-compatibility per §5.5: unknown labels not listed in `crit` are ignored by best-effort verifiers, while unknown labels listed in `crit` force rejection. The Sello-defined labels in this table (`sello_version`, `sello_token_ref`, `sello_log_url`) are part of the v0.1 profile and need not be listed in `crit` for a v0.1 verifier; `crit` exists to mark experimental extensions whose absence would be safe but whose presence MUST be understood.

The COSE_Sign1 signature is computed over the RFC 9052 §4.4 `Sig_structure` for context string `"Signature1"`, the exact protected header bytes, an empty external AAD byte string, and the embedded HPKE payload. Services MUST use empty external AAD, and owners MUST verify with empty external AAD.

### 5.2 HPKE encryption

The encrypted payload uses HPKE in single-shot mode:

- **KEM:** DHKEM(X25519, HKDF-SHA256) (ID 0x0020)
- **KDF:** HKDF-SHA256 (ID 0x0001)
- **AEAD:** ChaCha20-Poly1305 (ID 0x0003)
- **info:** CBOR canonical encoding (per RFC 8949 §4.2) of the array `["sello/0.1.0/receipt", service-identifier, sello_token_ref]`. The `service-identifier` value is the canonical identifier of the signing service as registered in the identity registry (§7) keyed by the protected header's `kid`. Both the signer and the verifier MUST use this registry-canonical value; it does not appear in the receipt body. The `sello_token_ref` value is the byte string from the protected header. Binding the info to these values prevents cross-context replay of the encrypted payload.
- **aad:** the COSE_Sign1 protected header bytes.

The plaintext is the CBOR-encoded receipt body (§5.3).

The COSE_Sign1 `payload` bstr is the HPKE output encoded as `enc || ct`, where `enc` is the 32-byte DHKEM(X25519, HKDF-SHA256) encapsulated key and `ct` is the AEAD ciphertext returned by HPKE single-shot sealing. Verifiers MUST parse the first 32 bytes of the payload as `enc` and the remaining bytes as `ct`. A payload shorter than 49 bytes (32-byte `enc` plus at least the 16-byte ChaCha20-Poly1305 tag and one byte of plaintext ciphertext) is structurally invalid and MUST be rejected before HPKE opening.

### 5.3 Receipt body

```cddl
receipt-body = {
  "agent-identifier" => agent-identifier,
  "action-type" => tstr,
  "action-input-hash" => sha256-digest,
  "action-output-hash" => sha256-digest,
  "result-status" => result-status,
  "timestamp" => #6.0(tstr),     ; CBOR tag 0, RFC 3339 string
  ? "service-defined-fields" => { tstr => map }   ; keyed by service-identifier
}

agent-identifier = tstr .regexp "^[0-9a-f]{32}$"
sha256-digest = bstr .size 32
result-status = "success" / "error" / "denied"
```

Field definitions:

- **agent-identifier**: A 32-character lowercase hexadecimal string deterministically derived from the authorization token. The service and the owner MUST compute it as `agent-identifier = lowercase-hex(SHA-256(authorization-token-bytes))[0:32]`, where `authorization-token-bytes` is the raw byte sequence of the JWS compact serialization the service received (§3.1) and the slice `[0:32]` takes the first 32 hex characters (the first 16 bytes of the 32-byte SHA-256 digest). The protected header field `sello_token_ref` (§5.1) is the full 32-byte digest of the same input; `agent-identifier` is its 16-byte truncation rendered as hex. Both values are derived from the same hash computation and never require coordination: any party holding the token computes them identically. Truncation to 16 bytes balances collision resistance (2^64 work to find a collision is adequate for distinguishing agents within an owner's own activity set) against receipt body size.
- **action-type**: A service-defined string identifying the action (e.g. "tools/call", "issues.create").
- **action-input-hash**: SHA-256 hash of the canonicalized action input. Canonicalization is JCS (RFC 8785) for JSON inputs, CBOR deterministic encoding (RFC 8949 §4.2) for CBOR inputs, and the raw byte sequence for non-structured inputs. The service MUST document which canonicalization applies to each `action-type`.
- **action-output-hash**: SHA-256 hash of the canonicalized action output, using the same canonicalization rules as `action-input-hash`. When `result-status` is `"denied"`, no action ran and no output exists; the service MUST set `action-output-hash` to the all-zeros 32-byte string as a sentinel value. The all-zeros value is a sentinel, not `SHA-256("")` (which is `e3b0c442...b7852b855`), and verifiers MUST NOT attempt to recompute or match an empty-input hash against it.
- **result-status**: One of "success", "error", "denied".
- **timestamp**: CBOR tag 0 (standard date/time string per RFC 8949 §3.4.1) carrying an RFC 3339 timestamp of action completion in UTC. Sub-second precision is permitted; note that owner-side replay dedup (§8.3) compares timestamps truncated to whole seconds together with the action type and action hashes, so finer precision is informational and cannot by itself be relied on for replay distinction.
- **service-defined-fields**: OPTIONAL service-specific metadata, scoped by service-identifier to prevent collisions when receipts from multiple services are aggregated. The outer map is keyed by a `tstr` holding the canonical service-identifier (the same value resolved from the identity registry per §7 and used in the HPKE `info` per §5.2). A service MUST place its custom fields ONLY under the map key that equals its own canonical service-identifier; a service MUST NOT write under another service's key. The value under that key is a CBOR `map` whose contents are defined by that service; the service MUST publish the schema of its custom field set alongside its identity registry entry. Verifiers that do not recognize a service-identifier key MUST preserve the entry unchanged (so it survives round-trips through tooling) and MAY surface it as an unknown-namespace warning. This structure trades one additional CBOR map nesting level for collision-freedom across the service ecosystem.

Three pieces of metadata that one might expect to find in the receipt body live elsewhere:

- The **schema version** is in the COSE_Sign1 protected header as `sello_version` (§5.1), allowing version detection before HPKE decryption is attempted.
- The **authorization token reference** is in the protected header as `sello_token_ref` (§5.1) and is also the indexable field used by owner queries (§4.2).
- The **service-identifier** is resolved from the identity registry (§7) keyed by the protected header's `kid`. The registry is the single source of truth for the `kid` → `service-identifier` → public key mapping; no duplicate appears in the body.

The action input and output are referenced by hash, not included verbatim. This keeps receipts small and avoids leaking input/output content even after decryption unless the owner has the original data on hand.

### 5.4 JSON debug rendering

For debugging and human inspection, decrypted receipts MAY be rendered as JSON with field names matching the CBOR labels. The JSON rendering MUST NOT be used for signing or verification.

### 5.5 Version Compatibility

The `sello_version` field in the COSE_Sign1 protected header (§5.1) is a semantic version string conforming to SemVer 2.0.0. Implementations parse it as MAJOR.MINOR.PATCH and apply the compatibility rules below.

**Pre-1.0 boundary rule.** SemVer 2.0.0 §4 designates MAJOR version zero (`0.y.z`) as initial development, in which any change may be breaking. For the lifetime of the 0.x series, Sello treats the MINOR component as the breaking-change boundary: v0.1 and v0.2 are wire-incompatible, while v0.1.0 and v0.1.7 are wire-compatible. The rules in this section that reference "MAJOR" apply to MINOR for any receipt whose MAJOR component is 0. From v1.0.0 onward, the rules apply to MAJOR as written and the 0.x special case ceases to apply.

**Major version handling.** A v0.1 implementation MUST reject any receipt whose `sello_version` has a MAJOR component the implementation does not understand (with the pre-1.0 substitution above: a v0.1 implementation MUST reject a v0.2 receipt). Rejection is reported to the owner as a distinct error condition, not silently dropped, so the owner can take corrective action (upgrade tooling, route the receipt through a translator, escalate to the service operator). An implementation MAY attempt best-effort parsing of receipts carrying a higher PATCH within a boundary it does understand: unknown fields in the receipt body are ignored, and unknown protected header parameters in the private-use range (-65536 to -262144) are ignored if the `crit` parameter (COSE label 2) does not mark them critical.

**Patch evolution within a boundary.** Within a single boundary version, the receipt body schema (§5.3) is permitted to grow by addition of new OPTIONAL fields. Within a single boundary version, the schema MUST NOT introduce new required fields, MUST NOT remove existing fields, MUST NOT change the type of an existing field, and MUST NOT change the semantics of an existing field. The same constraints apply to the protected header parameter set defined in §5.1.

**Protected header label stability.** The protected header parameter labels assigned in §5.1 from the COSE private-use range are fixed for the lifetime of a boundary version. A boundary bump MAY renumber these labels (for example, if standards-action labels become available via IANA registration per the IANA Considerations section). Implementations MUST NOT assume label assignments transfer across boundary versions.

**v0.1.x backward compatibility commitment.** No breaking changes to the on-wire format will be introduced within the v0.1.x series. Receipt envelopes produced by a v0.1.0 service MUST verify under a v0.1.x owner implementation for any x, and vice versa. Breaking changes are reserved for v0.2 and later.

**Cross-boundary upgrade story.** A v0.1 owner that encounters a receipt with `sello_version` set to a v0.2 value rejects the receipt per the rejection rule above (under the pre-1.0 boundary rule, v0.1 and v0.2 are wire-incompatible boundary versions). To consume the receipt, the owner has two options. Option one: upgrade the owner's verification tooling to a v0.2-aware build, which by the v0.2 compatibility commitment will also accept v0.1.x receipts the owner already has in storage. Option two: route the receipt through a translation proxy that converts a v0.2 envelope to a v0.1 envelope (re-encrypting, re-signing with a translator key registered in the identity registry per §7) for owners who cannot upgrade. The translator pattern is informational; v0.1 does not specify a translator wire format.

## 6. Transparency Log Integration

Sello is log-agnostic. The minimum log requirements are:

- **Append-only.** Once an entry is added, it cannot be removed or modified.
- **Merkle-tree commitment.** The log MUST commit to its contents via a Merkle tree, allowing inclusion proofs.
- **Witness cosigning.** The log MUST be cosigned by independent witnesses to prevent split-view attacks. A split-view attack is when a log operator presents different versions of the log to different observers, hiding entries from some parties while showing them to others; witness cosigning binds the log operator to a single Merkle root visible to all witnesses, making split-view detectable. Witness cosigning is what makes the log "public" in any operationally meaningful sense; without it, a log operator can serve different views to different observers.
- **Queryable by indexed metadata.** The log MUST support retrieval by an indexable field, at minimum by the `sello_token_ref` value in the COSE_Sign1 protected header.
- **Retrievable with proof.** The log MUST return an inclusion proof with each retrieved entry.
- **Verifiable integrated time.** The log SHOULD provide a verifiable integrated time for each entry, signed by the log operator alongside the entry's leaf and bound to the witnessed Merkle root that includes it. The §7.1 revocation rule depends on this; logs that cannot provide it expose receipts on revoked keys to the fail-closed branch of §7.1, regardless of when the receipt was actually published.

Log operators MAY operate as public goods (e.g. Sigstore Rekor) or as private federated instances. The spec does not mandate a specific log operator.

### 6.1 Sigstore Rekor profile

v0.1 reference implementations use Sigstore Rekor. Rekor v1 does not natively index arbitrary COSE protected-header values; reference implementations using Rekor MUST publish a paired off-log index keyed by `sello_token_ref`, or use a Rekor entry type that surfaces `sello_token_ref` as a queryable attribute. An unauthenticated off-log index is a discovery aid only: it can help owners find candidate entries, but it does not prove that all matching entries were returned. Owner implementations MUST NOT treat a query against an unauthenticated off-log index as a completeness proof for the receipt set. Deployments that need completeness guarantees MUST either use a log/index mechanism whose query result is itself authenticated, or run an independent audit process such as full-log scanning against witnessed roots. A future version of this spec MAY specify a canonical authenticated query approach as Rekor and SCITT-compatible logs evolve.

### 6.2 Log Discovery

Owners cannot retrieve receipts (§4.2) without knowing which transparency logs to query. The `sello_log_url` parameter in a receipt's protected header (§5.1) identifies where a single receipt was published, but the owner cannot read it without first retrieving the receipt, so it cannot bootstrap discovery on its own. Owners learn their trusted log set through one of the following mechanisms.

**Canonical log URL.** A log's protocol identity is its canonical log URL: an HTTPS URL consisting of scheme `https`, a lowercase host, an OPTIONAL explicit port, and a path prefix that identifies the log API root, with no query string, no fragment, no userinfo, and no trailing slash unless the path is exactly `/`. Default port `:443` MUST be omitted. Percent-encoding in the path MUST use uppercase hex digits, and characters in the unreserved set (ALPHA / DIGIT / "-" / "." / "_" / "~") MUST NOT be percent-encoded. The path MUST NOT contain dot segments (`.` or `..`) after URI parsing. Implementations MUST NOT follow redirects or otherwise rewrite log URLs when comparing identities. The `sello_logs` claim, static trusted-log configuration, `sello_log_url` protected header value, and the endpoint identity associated with returned inclusion proofs MUST all be represented in this canonical form. Equality is byte-for-byte string equality over these canonical URLs.

Examples:

| Input | Canonical? | Reason |
|-------|------------|--------|
| `https://rekor.example.com/api` | yes | HTTPS, lowercase host, path identifies the API root |
| `https://rekor.example.com/api/` | no | trailing slash is not allowed unless the path is exactly `/` |
| `https://Rekor.Example.com/api` | no | host is not lowercase in the stored string |
| `https://rekor.example.com:443/api` | no | default port `:443` must be omitted |
| `https://rekor.example.com/api?x=1` | no | query strings are not part of log identity |
| `https://rekor.example.com/api#v1` | no | fragments are not part of log identity |
| `http://rekor.example.com/api` | no | scheme must be `https` |

The practical rule is simple: choose one canonical base URL for each log, store exactly that string in the owner's trusted log set, place exactly that same string in `sello_log_url`, and compare exactly that same string when verifying the returning log.

**Preferred default (v0.1).** The token issuer publishes the owner's trusted log set as a JWS claim named `sello_logs` in the same authorization token that carries the owner's HPKE public key (per §3.1). The claim value is a JSON array of canonical log URL strings, each identifying a transparency log meeting §6's requirements. The owner extracts this list at token-issuance time and persists it as the trusted log set for any receipts tied to that authorization token. Because the claim is carried inside a JWS signed by the token issuer, the owner's trust in the log set inherits from their trust in the token issuer. A service implementing the v0.1 JWS token profile MUST publish the receipt to one of the logs listed in `sello_logs` when the claim is present and non-empty, and MUST place that same canonical log URL byte-for-byte in `sello_log_url`. If the claim is absent or empty, the service MUST either use a log it knows through local policy to be owner-trusted under §6.2 or fail receipt generation with an explicit error; publishing to an arbitrary §6-compatible log is not sufficient for Sello conformance.

**Alternative: static configuration.** The owner MAY maintain a static list of trusted canonical log URLs in their verification tooling configuration, independent of any token claim. This is appropriate when the owner operates within a fixed deployment that always uses the same logs, or when the token format in use does not yet support custom claims.

**Alternative: agent-forwarded hints.** The agent MAY forward observed `sello_log_url` values to the owner out of band (for example, via the agent's operator-side telemetry), giving the owner a candidate set of logs to consult. This mechanism is a hint only; the owner MUST cross-check any forwarded URL against their trusted set established by one of the two mechanisms above before querying.

**Trust boundary.** The owner MUST query every log in their trusted set when reconstructing activity for a given `sello_token_ref`, because a receipt may have been published to any log the service chose from the set the service believes the owner trusts. The owner MUST reject any receipt whose `sello_log_url` is not byte-for-byte equal to the returning log's canonical URL, or whose returning log's canonical URL is not present in the owner's trusted log set, even if the receipt's COSE_Sign1 signature and inclusion proof verify correctly. Witness cosigning trust is per-log: a valid inclusion proof against an untrusted log's Merkle root does not establish the tamper-evidence guarantee Sello relies on (§2, P3), so cryptographic validity alone is insufficient.

A future version of this spec MAY define a `.well-known/sello-logs` discovery endpoint at the token issuer's domain as a fallback for tokens that cannot carry the `sello_logs` claim directly.

## 7. Server Identity Registry

**This section is intentionally minimal. Server identity verification is the largest unsolved problem in Sello v0.1.**

For v0.1, implementations MAY use any of:

- A JSON file maintained in the project repository mapping each `kid` to its canonical `service-identifier` and public key.
- DNS TXT records at the service's domain.
- OIDC keyless signing via Sigstore Fulcio.
- X.509 certificate chains.

A future v0.2 will specify a canonical mechanism. Implementations are encouraged to experiment and contribute to the discussion.

### 7.1 JSON Identity Registry Profile

v0.1 reference implementations resolve `kid` to service-identifier and public key through a signed JSON registry file. The file is a JSON object whose top-level keys are the lowercase hex encoding of the `kid` byte string from the protected header (§5.1), and whose values are objects with two required fields: `service_identifier` (string, the canonical identifier consumed by the HPKE `info` construction in §5.2) and `public_key_ed25519` (string, base64url encoding without padding of the raw 32-byte Ed25519 public key, 43 characters). The registry's JSON field names use snake_case per common JSON convention, while the CBOR receipt body field names in §5.3 use kebab-case per common CBOR/CDDL convention; this difference is intentional and follows each format's idiomatic style rather than reflecting a semantic distinction.

The registry file MUST itself be signed. A trust root operator holds a long-term Ed25519 key, and publishes alongside the registry file a detached signature over the exact bytes of the JSON file. The signature is encoded as base64url and served at the registry URL with the suffix `.sig`. Owners MUST verify this signature against a pre-configured trust root public key before consulting any entry. A registry whose signature does not verify MUST be rejected in full; partial trust is not permitted. The mechanism by which an owner obtains the trust root public key in the first place is out of scope for this version, per §9 (server identity registry mechanism); v0.1 implementations typically ship a trust root pubkey baked into the verification tool's configuration, leaving the bootstrap question to a future spec revision.

Distribution is by stable HTTPS URL or by commit in a public git repository at a stable path. Multiple trust roots MAY publish parallel registries with overlapping or disjoint coverage. Owners choose which trust roots to honor; the choice is a local policy decision and is not negotiated through the protocol. Reference implementations SHOULD cache the registry file with a freshness interval no longer than 24 hours.

Rotation is additive. To rotate, the service generates a new key pair and the trust root appends a new `(kid, service_identifier, public_key_ed25519)` entry under a new `kid`. The previous `kid` remains in the registry and remains valid for verifying receipts that were signed before rotation. A receipt's validity is determined by whether its `kid` resolves at the time of verification, not by which `kid` is currently in active use by the service.

Revocation is published as a sibling JSON object `revoked` at the top level of the same file, mapping each revoked `kid` (hex string) to an object with one required field `revoked_at` (RFC 3339 UTC timestamp). Owners MUST reject any receipt whose `kid` appears in `revoked` and whose transparency-log integrated time is at or later than `revoked_at`. The integrated time is the timestamp assigned by the log to the witnessed entry, not the receipt body's service-asserted `timestamp` (§5.3). Receipts whose integrated time is before `revoked_at` remain verifiable, which preserves the historical record when a key is rotated for hygiene rather than compromise. If the log cannot provide a verifiable integrated time for an entry, owners MUST treat the receipt as revoked whenever its `kid` appears in `revoked`. A trust root that wishes to invalidate all prior receipts under a compromised key sets `revoked_at` to a time earlier than the key's first witnessed log entry.

## 8. Security Properties and Threat Model

Sello's properties depend on three trust assumptions. First, at least one service the agent calls must be honest and uncompromised; if every service colludes with the agent operator, Sello cannot detect what they jointly fabricate. Second, the transparency log must be honestly witness-cosigned, since a log operator colluding with every witness can present a split view to the owner. Third, the owner controls their HPKE private key: loss of the key makes past receipts permanently undecryptable, and compromise of the key breaks confidentiality (§8.3). If any of these assumptions fails, the properties in §8.2 degrade in the ways documented in §8.3.

### 8.1 Adversary capabilities assumed

The threat model assumes an adversary who:

- May compromise the agent and arbitrarily edit its local logs.
- May control the agent's operator infrastructure.
- May read the public transparency log.
- May submit arbitrary bytes to the log, including bytes that purport to be Sello receipts but cannot pass §4.2 verification without possession of a service's signing key.

The adversary is assumed NOT to possess:

- The Ed25519 signing keys held by legitimate services.
- The HPKE private key of the agent owner.

### 8.2 Properties provided

**Integrity of recorded actions.** A receipt signed by a legitimate service's key cannot be modified without detection. Verifying the COSE_Sign1 signature proves the receipt was emitted by the key-holder and has not been altered.

**Confidentiality of receipt contents.** Receipts on the public log are encrypted to the owner. Other parties (including the log operator, witnesses, and adversaries scraping the log) cannot read the contents.

**Tamper-evidence of logged receipts.** The Merkle log structure ensures that modification or removal of a known logged receipt after publication is detectable. Completeness of retrieval depends on the query mechanism: unauthenticated metadata indexes can omit matching receipts without invalidating inclusion proofs for the receipts they do return (§6.1). Deployments that need tamper-evidence for the full receipt set must use authenticated query results or independent log auditing.

**Independence of attestation.** Because the signing key is held by the receiving service, a compromised agent or operator cannot forge receipts. Forgery requires compromise of the service.

### 8.3 Limitations and known attacks

**Suppression attack.** An adversary controlling the agent can prevent the agent from calling services entirely, producing no receipts. Sello does not solve this. Missing receipts are an indirect signal, not a direct one.

**Service collusion.** If a service colludes with the agent operator to emit false receipts, Sello cannot detect this from a single receipt. Plurality of services and cross-checking across receipt sets is the partial mitigation.

**Service replay.** A service holding its signing key MAY re-emit a previously-observed event by re-encrypting and re-signing it, producing a new envelope that passes verification but represents activity that did not occur. HPKE single-shot encryption uses fresh randomness per call, so the replayed envelope is not byte-identical to the original and cannot be filtered by simple deduplication on the log side. Owner-side reconstruction MUST de-duplicate receipts only when they share `kid`, `sello_token_ref`, `timestamp` truncated to whole seconds, `action-type`, `action-input-hash`, and `action-output-hash` (treating them as a single logical event). Receipts that share only `kid`, `sello_token_ref`, and a whole-second timestamp but differ in action type or hashes MUST be preserved as distinct events and SHOULD be flagged as high-frequency same-second activity rather than collapsed. Detection beyond the dedup rule requires corroborating receipts from other independent services: if a real event involved calls to multiple services, only the genuine event has receipts from all of them. Sello does not provide stronger guarantees against a service that replays its own receipts.

**Metadata leakage on the public log.** The COSE_Sign1 protected header is not encrypted. The `kid` field reveals which service signed each receipt; the `sello_log_url` and `sello_version` reveal protocol parameters. A passive observer of the log can therefore derive traffic-pattern information (which services an agent talks to, at what rate) even though receipt contents remain confidential. Implementations that need stronger metadata confidentiality MAY use rotating per-call key identifiers and obscure the `kid`-to-service mapping in the identity registry, accepting the additional registry complexity. If `sello_log_url` is removed from the protected header in a future version (see §13 Q3), this leakage source drops; the residual leakage from `kid` and `sello_version` remains.

**Token reference enumeration.** The `sello_token_ref` is a hash of the authorization token. If the underlying token has low entropy, an adversary holding any matching token can compute the same `sello_token_ref` and retrieve every receipt for that token from the public log. Authorization tokens used with Sello MUST contain at least 128 bits of unpredictable entropy.

**Compromised service key.** If a service's Ed25519 private key is stolen, an adversary can sign arbitrary receipts until the key is revoked. The JSON registry profile in §7.1 bounds acceptance using the receipt's verifiable log integrated time; deployments using other registry mechanisms MUST provide an equivalent time-bound revocation rule. Dispute handling for receipts witnessed before the compromise time remains an operational matter outside v0.1.

**Owner key loss.** If the owner loses their HPKE private key, past receipts become permanently undecryptable. Key escrow and recovery mechanisms are out of scope.

## 9. Out of Scope

The following are deliberately not specified in v0.1 and are flagged for future work:

- Server identity registry mechanism (§7).
- Canonical service key lifecycle governance beyond the JSON registry profile in §7.1.
- Authorization token authorization semantics and non-JWS token profiles. v0.1 conformance uses the JWS token profile in §3.1; future revisions may define equivalent profiles for UCAN, biscuits, macaroons, or other token formats.
- Cross-log federation and witness cosigning protocols.
- Privacy-preserving aggregate queries against the log.
- Owner key management, escrow, and recovery.
- Performance characteristics under high call volumes.

## 10. Operational Considerations

This section gives non-normative guidance for service implementers. It does not change the wire format or the verification rules in §4 and §5.

### 10.1 Submission retry

If log submission fails (network failure, log unavailable, transient error), the service SHOULD retry with exponential backoff. The service MAY queue receipts to a local durable store while retrying. The service MUST NOT discard a receipt without notifying the owner. The notification mechanism is out of scope for v0.1.

### 10.2 Offline operation

A service that cannot reach a log MAY emit receipts directly to the agent for owner forwarding, as permitted by §4.1 step 8. Both parties MUST understand that receipts delivered this way carry signature-only guarantees and lack inclusion proofs until the service later submits them to the log. The service SHOULD submit any locally-queued receipts as soon as the log becomes reachable.

### 10.3 Batch submission

Services with high call volume MAY batch-submit receipts to the log. Batching MUST NOT alter the receipt body or signature; each receipt remains independently verifiable per §4.2.

### 10.4 Clock skew

Service timestamps SHOULD be within ±5 minutes of UTC. Owners MAY reject receipts whose timestamps are more than 24 hours in the future or more than 90 days in the past, but the rejection policy is implementation-specific.

### 10.5 Receipt size budget

A typical CBOR-encoded receipt body (§5.3) without `service-defined-fields` runs ~150-250 bytes: agent-identifier (~36 B as a 32-char tstr plus key overhead), action-type (~20-40 B), two hash bstrs (~38 B each including length prefix), result-status (~25 B), and a tag-0 RFC 3339 timestamp (~35 B). Adding HPKE overhead (32-byte encapsulated X25519 key plus 16-byte AEAD tag) and COSE_Sign1 overhead (protected header bytes plus 64-byte Ed25519 signature) brings the on-wire envelope to roughly 350-500 bytes for a no-extension receipt. Services that populate `service-defined-fields` should budget accordingly; large custom field sets can push the envelope well past 1 KB. Services with very large action inputs or outputs MUST still hash them (§5.3); the receipt body remains bounded regardless of input/output size.

### 10.6 Log capacity awareness

Services SHOULD be aware that public goods logs (e.g. Sigstore Rekor) have rate limits and capacity constraints. High-volume services SHOULD use private federated log instances per §6 rather than relying on shared public infrastructure.

## 11. Reference Implementation

The TypeScript reference implementation exercises the full receipt lifecycle with fixed keys and a mock transparency log:

- A mock service that emits one or more receipts.
- A mock owner that verifies and decrypts receipts.
- A local in-memory transparency log.
- Compact JWS token verification.
- COSE_Sign1 receipt envelopes.
- HPKE encryption to the owner.
- Owner-side verification.
- MCP middleware prototype.
- Rekor discovery adapter with explicit discovery-only completeness.
- Tests covering the happy path, common tampering failures, and implementation-backed test vectors.

Future implementation work may add live Rekor proof verification, production identity operations, an owner-side CLI, and external interoperability fixtures.

## 12. Prior Art

Sello builds on substantial prior work in adjacent areas. The following projects use the "receipts" vocabulary in AI agent contexts and informed the design of Sello:

- **Agent Receipts** (Otto Jongerius, agentreceipts.ai). Open spec for operator-signed agent receipts using Ed25519 and W3C VCs.
- **Signet** (Prismer-AI org, github.com/Prismer-AI/signet). MCP middleware with bilateral co-signing in v0.4 and encrypted envelopes in v0.10.
- **Agent Passport System** (Tymofii Pidlisnyi, github.com/aeoess/agent-passport-system). Includes ActionReceipt, AuthorityBoundaryReceipt, CustodyReceipt, ContestabilityReceipt primitives.
- **draft-farley-acta-signed-receipts-01** (T. Farley, ScopeBlind). IETF draft for signed decision receipts.
- **draft-nivalto-agentroa-route-authorization-00** (Joseph Michalak, Nivalto). IETF draft for Agent Execution Receipts.
- **SCITT working group at IETF.** Supply Chain Integrity, Transparency, and Trust. Canonical IETF framework for COSE_Sign1 transparency receipts.

Sello draws on foundational cryptographic and architectural prior art:

- **Heinrich, A. et al.** "Who Can Find My Devices? Security and Privacy of Apple's Crowd-Sourced Bluetooth Location Tracking System." PoPETs 2021, Issue 3, pp. 227-245. Analysis of the Find My protocol whose architectural inversion Sello ports to AI agents.
- **Syta, E. et al.** "Keeping Authorities 'Honest or Bust' with Decentralized Witness Cosigning." IEEE S&P 2016. The witness cosigning protocol underpinning modern transparency logs.
- **RFC 6962, RFC 9162.** Certificate Transparency.
- **RFC 9052.** CBOR Object Signing and Encryption (COSE).
- **RFC 9180.** Hybrid Public Key Encryption (HPKE).
- **Sigstore project.** Rekor transparency log, Fulcio identity, the keyless signing pattern.

The contribution of Sello is the combination of these existing primitives for the specific use case of AI agent action attestation, with the specific architectural choice that the receiving service is the signer.

### 12.1 Relation to W3C Verifiable Credentials

Several adjacent receipt projects (Agent Receipts, APS) use W3C Verifiable Credentials as the receipt format. Sello uses COSE_Sign1 wrapping an HPKE-encrypted CBOR body, published to a transparency log. This is a deliberate architectural choice driven by Sello's specific threat model, not a comment on the quality of VC-based projects.

Three considerations led to the COSE choice. First, compactness: CBOR is materially smaller than JSON-LD, which matters when every service call produces a log entry and the log substrate charges by size and entry count. Second, transparency-log fit: Sigstore Rekor and the SCITT signed-statement profile speak DSSE and COSE_Sign1 natively, so a COSE-shaped receipt slots into the existing log substrate without a translation layer. Third, encryption-at-rest on the log: VCs are typically broadcast in cleartext or selectively disclosed at presentation time, whereas Sello's threat model (§8.1) requires that receipt contents be confidential on shared public infrastructure. HPKE-inside-COSE gives explicit, AEAD-authenticated encryption to a specific owner key; layering equivalent confidentiality onto a VC pipeline is possible but adds protocol surface.

The log choice is the other half. Sello's tamper-evidence and split-view resistance come from Merkle commitment plus witness cosigning (§6); a VC-issuance-only architecture, even with revocation lists, does not provide either. The two are not interchangeable.

Interop direction: a Sello receipt body could be rendered as a VC for tooling that expects that shape. The natural place is the JSON debug rendering described in §5.4, which is explicitly non-normative for verification. The signature and the transparency-log binding remain in the COSE layer regardless; the VC rendering is a presentation concern.

### 12.2 Relation to Operator-Signed Receipts

A second family of adjacent work signs receipts on the operator's side of the trust boundary: Agent Receipts (in its original operator-signed form), Pipelock's out-of-process mediator signer, draft-farley's policy-gateway signer, and various in-house variants. These systems are valuable for fast, cheap, ubiquitous coverage of agent activity and are easier to deploy than Sello.

In the §8.1 threat model, operator-signed receipts are weaker than Sello along one axis: the signing key sits on the operator's side of the trust boundary, so an operator compromise (or an adversarial operator) can forge receipts without detection. Sello's **P1** is precisely the move that closes this gap. Along two other axes, operator-signed receipts are stronger: (a) lower deployment burden, since the operator already holds the agent's full context and does not need each service to implement anything, and (b) coverage of calls to services that have not implemented Sello.

Pragmatically, a real deployment will likely emit both kinds of receipts. Operator-signed receipts provide the cheap full-trace path covering every call the agent makes. Sello receipts form the strong-attestation backbone for the calls that matter most: regulated, high-value, or security-relevant interactions where receiver-side signing is worth the integration cost. The two ecosystems can and should coexist. Sello does not seek to displace operator-signed receipts; it complements them.

A natural integration point is the service-side library. An MCP server library, for example, can emit an operator-signed VC over each call for the cheap-trace ecosystem AND a Sello receipt to the transparency log for the strong-attestation ecosystem, from the same per-call hook. Owners then consume whichever record their use case demands.

## 13. Open Questions

Several design questions in v0.1 are intentionally left open for community input before v0.2. The following are the most substantive; contributions on any of them are welcome (§14).

**Q1. Service-supplied nonce in the receipt body.** Should the receipt body include a service-supplied nonce to enable stronger replay detection beyond the dedup key in §8.3? A nonce would let owners detect that two receipts are intentional duplicates by the same service versus a replay, even when the same action is repeated with the same input and output within one second. The trade-off is that a nonce only helps if owners can corroborate it against the service's own records, which reintroduces an out-of-band trust dependency. Note also that the v0.1 receipt body already permits a service to carry a nonce in its own `service-defined-fields` namespace (§5.3) without any spec change; the open question is therefore whether the spec should normalize a nonce field across services, not whether services can experiment with one today. Current draft position: no standardized nonce in v0.1; rely on §8.3 dedup and cross-service corroboration, and let services that need stronger per-receipt distinctiveness use `service-defined-fields` until v0.2 considers normalization.

**Q2. Shape of `agent-identifier`.** §5.3 currently derives `agent-identifier` as a 16-byte truncation of SHA-256 over the authorization token. Should this be a hash, a UUID assigned at agent provisioning, or an opaque issuer-defined string? A hash binds the identifier to the token but leaks correlation across services that see the same token. A UUID is service-agnostic but requires a provisioning step. An opaque issuer-defined string is the most flexible but the least interoperable. Current draft position: hash-based derivation as specified in §5.3; revisit when a canonical token spec stabilizes.

**Q3. `sello_log_url` in the protected header.** Given that log discovery is now spec'd in §6.2, should `sello_log_url` remain in the protected header? Keeping it makes single receipts self-contained and verifiable without a registry roundtrip. Removing it shrinks the envelope and reduces metadata leakage on the public log (§8.3). The case for removal has sharpened since §6.2 was added: an owner MUST reject any `sello_log_url` that does not identify the returning trusted log, so the URL the service writes into the protected header is only a consistency binding, never load-bearing for the owner's trust decision. The only reader the URL helps is a verifier with no out-of-band log knowledge, which §6.2 says should not exist in a compliant deployment. Current draft position: keep `sello_log_url` for v0.1 to preserve self-containment for debugging and informal tooling; v0.2 SHOULD remove it from the protected header unless a concrete consumer surfaces during the v0.1 review period.

**Q4. HPKE base mode versus auth mode.** v0.1 uses HPKE base mode (§5.2). Auth mode cryptographically binds the sender's identity into the HPKE context, which would provide a second binding of service identity to ciphertext beyond the outer COSE_Sign1 signature. The trade-off is operational: auth mode requires the service to hold an HPKE static key in addition to its Ed25519 signing key. Current draft position: base mode; the COSE_Sign1 signature already binds the service.

**Q5. Signing algorithm agility.** Is Ed25519 the right default, or should the spec also profile P-256 (for ecosystems with HSM constraints) and ML-DSA (for post-quantum migration)? Ed25519 is small, fast, and ubiquitous in modern transparency-log tooling. P-256 is required by some compliance regimes. ML-DSA is the NIST PQ signature standard and will become relevant on a multi-year horizon. Current draft position: Ed25519 only in v0.1; algorithm agility added in v0.2 once the SCITT and Sigstore ecosystems make their PQ choices.

**Q6. SCITT signed-statement alignment.** Should Sello align directly with SCITT's signed-statement format, or maintain its own COSE_Sign1 profile? Direct alignment maximizes interop with the broader SCITT ecosystem and means Sello receipts are valid SCITT statements out of the box. Maintaining a separate profile lets Sello move faster on the agent-specific fields without waiting for SCITT WG consensus. Current draft position: keep a Sello profile of COSE_Sign1 in v0.1; pursue explicit SCITT compatibility in v0.2 as the SCITT format stabilizes.

## 14. Contributing

This spec is a working draft. Issues, pull requests, and counterproposals are welcome in the repository where this document is published. The author is particularly interested in:

- Critique from the SCITT working group on alignment with the SCITT receipts profile.
- Critique from the MCP team on integration with the MCP authorization spec.
- Critique from the Signet, Agent Receipts, and APS maintainers on whether Sello's architecture should be absorbed into their existing projects rather than implemented separately.

The author does not intend to be the sole long-term maintainer of this spec. Contributions and forks are welcome.

## 15. Process and Venue

This section describes how the spec is governed.

**Document format.** v0.1 lives as a Markdown document in a public repository. v0.2 onwards MAY move to xml2rfc format if the spec is adopted by an IETF working group, most likely SCITT.

**Versioning.** The spec uses semantic versioning. Breaking changes require a boundary bump per §5.5: MINOR during the 0.x series (so v0.1 → v0.2 is a breaking bump), MAJOR from v1.0.0 onward. Non-breaking additions go in the next component below the boundary (PATCH during 0.x, MINOR from v1.0.0). Editorial fixes go in patch versions.

**Maintainership.** v0.1 was authored by the author listed in §16. Ongoing maintenance is intended to transition to either an IETF working group or a multi-party stewardship group within six months of v0.1 publication. The author does not intend to be the sole long-term maintainer.

**Decision-making.** Changes require either rough consensus on the public issue tracker or adoption by a successor maintainer. Until v0.2 ships or a maintainer transition completes (whichever comes first), the author of v0.1 retains a soft veto on changes that contradict the four design properties in §2.

**Coordination with adjacent specs.** The spec is open to absorption by SCITT, the MCP authorization spec, Agent Receipts, or any adjacent effort if the community judges that a better outcome than maintaining Sello as a standalone document. Forks for divergent designs are equally welcome.

## 16. Authors

Juan Figuera

## 17. Acknowledgments

Acknowledgments will be added as community review progresses.

## 18. IANA Considerations

The COSE_Sign1 protected header parameter labels used in this spec (-65537, -65538, -65539; see §5.1) are drawn from the COSE Header Parameters private use range (-65536 to -262144) and require no IANA action.

If a future version of this specification is brought through the IETF process, the following IANA actions are anticipated:

- Registration of the `sello_version`, `sello_token_ref`, and `sello_log_url` parameters in the COSE Header Parameters registry, with labels assigned from the standards-action range.
- Registration of a media type for the encoded receipt envelope (suggested: `application/sello-receipt+cose`).

Implementations conforming to v0.1 SHOULD NOT depend on these registrations existing.

## 19. Document History

- 0.1.0-draft (2026-05-28): Initial public draft.

## Appendix A: Worked Example

This appendix walks through a single MCP tool call end to end. All hex values shown are placeholders; an implementation generating actual receipts will compute different (real) values. The example is illustrative of structure, not a test vector.

### A.1 Scenario

An agent calls the MCP method `tools/call` on the service `github.com/mcp/v1`, asking it to create an issue. The agent presents a compact JWS authorization token whose SHA-256 hash is `<token_hash>`. The token payload contains `owner_hpke_pk` with value `<owner_hpke_pk>` and `sello_logs` containing `"https://rekor.example.com/api"`. The service verifies the JWS signature before extracting either claim. The service holds Ed25519 signing key pair `<svc_sign_sk>` / `<svc_sign_pk>`, identified by a `kid` byte string holding the UTF-8 encoding of `"github-mcp-v1-2026-q2"`.

### A.2 Build the receipt body

The service constructs the receipt body in CBOR diagnostic notation:

```
{
  "agent-identifier": "<agent_id_derived_from_token>",
  "action-type": "tools/call",
  "action-input-hash": h'<sha256_of_jcs_canonicalized_input>',
  "action-output-hash": h'<sha256_of_jcs_canonicalized_output>',
  "result-status": "success",
  "timestamp": 0("2026-05-27T14:32:11Z")
}
```

Encoded as canonical CBOR per RFC 8949 §4.2, this yields the plaintext byte string `<plaintext_cbor>`.

### A.3 HPKE-encrypt to the owner

The service runs HPKE single-shot encryption:

- **Suite:** DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305
- **Recipient public key:** `<owner_hpke_pk>`
- **info:** CBOR canonical encoding of `["sello/0.1.0/receipt", "github.com/mcp/v1", h'<token_hash>']`
- **aad:** the COSE_Sign1 protected header bytes (computed in A.4)
- **plaintext:** `<plaintext_cbor>` from A.2

HPKE produces an encapsulated key `<enc>` and ciphertext `<ct>`. The HPKE payload is the concatenation `<enc> || <ct>`.

### A.4 Wrap in COSE_Sign1

The service builds the protected header:

```
{
  1: -8,                                    ; alg: EdDSA
  4: h'<kid_bytes>',                        ; kid (UTF-8 bytes of "github-mcp-v1-2026-q2")
  -65537: "0.1.0",                          ; sello_version
  -65538: h'<token_hash>',                  ; sello_token_ref
  -65539: "https://rekor.example.com/api"   ; sello_log_url
}
```

CBOR-encodes the protected header, signs the COSE_Sign1 `Sig_structure` with `<svc_sign_sk>`, and produces the final COSE_Sign1 array `[protected, {}, hpke_payload, signature]`.

### A.5 Submit to the log

The service POSTs the COSE_Sign1 array to the transparency log specified by canonical `sello_log_url`, which is also present byte-for-byte in the token's `sello_logs` trusted set. The log returns an inclusion proof `<proof>`, a signed log root, and a verifiable integrated time. Per §6.1, an implementation using Rekor v1 also writes `(sello_token_ref, log_index)` to its paired off-log index so the owner's query in A.6 can find this entry; that index is a discovery aid unless it provides authenticated completeness.

### A.6 Owner retrieval and verification

Later, the owner queries every log in the trusted set for entries with `sello_token_ref == <token_hash>`. The log returns matching envelopes with their inclusion proofs.

For each entry, the owner:

1. Confirms the protected-header `sello_log_url` is byte-for-byte equal to the canonical URL of the trusted log that returned the entry and proof.
2. Verifies the inclusion proof against a witness-cosigned log root.
3. Looks up the signing service in the identity registry (§7) by `kid`, obtaining the service public key and the canonical `service-identifier`.
4. Applies the §7.1 revocation rule using the returning log's integrated time.
5. Verifies the COSE_Sign1 signature with the service's public key.
6. Reconstructs the HPKE `info` from the registry-resolved `service-identifier` and the `sello_token_ref` in the protected header.
7. Decrypts the HPKE payload using the owner's HPKE secret key, with the protected header bytes as `aad`.
8. CBOR-decodes the plaintext into a receipt body.

If log-binding, inclusion-proof verification, revocation checking, signature verification, and HPKE decryption all succeed, the receipt is valid. The owner now has an independently-attested record that `github.com/mcp/v1` observed a `tools/call` from this agent at the recorded timestamp.

### A.7 Denied case

This subsection shows a receipt produced when the service rejects the call. Suppose the agent presents a valid authorization token but the token's scope does not permit the requested `tools/call` target. The service does not perform the action. It still produces a receipt: Sello records the denial as much as the success, because an owner reconstructing the trail needs to see "the agent tried to do X and was denied" as evidence of intent. The service constructs the receipt body with `result-status: "denied"` and sets `action-output-hash` to 32 bytes of zeros (no output was produced). The body then goes through the same HPKE-encrypt, COSE_Sign1, and log-submit flow described in A.3 through A.5. Owner-side verification (A.6) is unchanged.

```
{
  "agent-identifier": "<agent_id_derived_from_token>",
  "action-type": "tools/call",
  "action-input-hash": h'<sha256_of_jcs_canonicalized_input>',
  "action-output-hash": h'0000000000000000000000000000000000000000000000000000000000000000',
  "result-status": "denied",
  "timestamp": 0("2026-05-27T14:33:02Z")
}
```

See Appendix B and `fixtures/vectors/sello-v0.1.json` for exact byte-level renderings of success, error, and denied receipts.

## Appendix B: Test Vectors

The reference implementation publishes implementation-backed v0.1 vectors in `fixtures/vectors/sello-v0.1.json`. These vectors replace the earlier illustrative byte strings: the compact JWS tokens, SHA-256 digests, COSE_Sign1 envelopes, HPKE payloads, Ed25519 signatures, decrypted receipt bodies, signed JSON registry, and mock-log proofs are generated by the implementation and verified by the test suite.

The fixture currently contains three receipts:

- `success`: a successful `tools/call` receipt.
- `error`: an accepted service call whose downstream action failed.
- `denied`: a policy-denied call whose `action-output-hash` is the all-zero SHA-256 digest.

Each vector includes:

- The compact JWS authorization token and issuer Ed25519 key material.
- The owner X25519 HPKE key material.
- The service `kid`, service identifier, Ed25519 key material, and signed registry JSON.
- The expected `sello_token_ref` and `agent-identifier` derived from the exact compact JWS bytes.
- The protected-header bytes, HPKE `enc || ct` payload, full COSE_Sign1 envelope, decrypted receipt body CBOR, and decoded receipt body fields.
- The mock log proof binding the log URL, index, integrated time, and exact envelope hash.

Conformant implementations should validate each vector as follows:

1. Verify the compact JWS signature before reading `owner_hpke_pk` or `sello_logs`.
2. Compute SHA-256 over the exact compact JWS bytes and compare it with `sello_token_ref`; compare the first 16 digest bytes rendered as lowercase hex with `agent-identifier`.
3. Decode the COSE_Sign1 envelope and protected header, enforcing the structural rules in §5.1.
4. Verify the COSE_Sign1 signature with empty external AAD and the service public key resolved from the signed registry.
5. Reconstruct HPKE `info` from `["sello/0.1.0/receipt", service_identifier, sello_token_ref]`, use the exact protected-header bytes as AAD, and decrypt the payload with the owner private key.
6. Decode and validate the receipt body per §5.3.
7. Confirm that changing any protected-header, payload, signature, registry, or receipt-body byte causes verification to fail at the appropriate stage.

The reference test `test/vectors/sello-v0.1.test.ts` performs these checks from the published fixture bytes. Future vector files SHOULD preserve this shape and add a new fixture filename when the wire format changes across a Sello boundary version.
