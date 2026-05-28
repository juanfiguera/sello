# Performance And Receipt Size

Sello includes a small local benchmark for tracking rough receipt size and implementation performance:

```sh
node --run bench
node --run bench -- --iterations 500 --json
```

The benchmark uses the reference implementation with fixed local keys and the mock transparency log. It reports:

- CBOR receipt body size.
- COSE protected-header size.
- HPKE payload size.
- Full COSE_Sign1 envelope size.
- Mock proof JSON size.
- Average receipt creation time.
- Average one-receipt verification time.
- Batch verification time and per-receipt average.

These numbers are useful for local regression tracking and integration planning. They are not formal cryptographic benchmarks: results vary by CPU, Node version, OS, and thermal state, and the mock log is not a live Rekor deployment.

For production capacity planning, measure against the real service middleware, real action payload canonicalization, the chosen log adapter, and the deployment's key storage path.
