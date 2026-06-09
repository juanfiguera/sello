# Security Policy

Sello is an early protocol draft and reference implementation. Security review is welcome, but the current package is not a production-ready cryptographic system.

## Reporting Sensitive Issues

If you find a vulnerability that could expose keys, plaintext receipts, authorization tokens, forged receipts, invalid verification results, or remote code execution, please do not post exploit details publicly.

Use GitHub private vulnerability reporting for this repository if it is available. If it is not available, open a minimal issue saying you have a security report and ask for a private channel. Please avoid including secrets, exploit payloads, or unpublished attack details in that first public issue.

For non-sensitive protocol questions, threat-model gaps, documentation issues, and hardening suggestions, public issues and pull requests are welcome.

## Helpful Report Details

When possible, include:

- Affected version or commit.
- Which area is involved: token verification, receipt signing, HPKE encryption, COSE verification, log inclusion, revocation, CLI, or docs.
- Reproduction steps or a minimal test case.
- Expected impact.
- Whether the issue affects local dev mode, self-hosted production use, hosted use, or the protocol itself.

## Known Deferred Work

The following are known gaps and should not be treated as newly discovered production regressions unless the docs or code claim they are complete:

- Live Rekor inclusion-proof verification and witnessed-root validation.
- Production identity, registry, and key lifecycle operations.
- Durable receipt queues for background submission.
- Hosted dashboard decryption and delegated viewer keys.
- Managed remote signing.
- External audits of the local HPKE and COSE implementations.

See [docs/security-review.md](docs/security-review.md) and [docs/sdk-security-audit.md](docs/sdk-security-audit.md) for the current review notes.

## Bounty

There is no paid bug bounty program at this time.

