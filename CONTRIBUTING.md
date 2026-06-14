# Contributing

Thanks for taking a look at Sello. This is an early protocol and reference implementation, so careful review is especially valuable.

## Good First Contributions

- Try the local loop and report where the setup feels confusing.
- Review `SPEC.md` for ambiguity, missing threat-model notes, or interoperability risk.
- Add focused tests for receipt creation, verification, CLI flows, and examples.
- Improve docs when a step can be shorter, clearer, or more honest.

## Development

Install dependencies:

```bash
npm install
```

Run the main checks:

```bash
node --run test
node --run package:test
```

Run the Python SDK checks:

```bash
python -m pip install ./python
python -m unittest discover -s python/tests
```

For a local receipt loop:

```bash
npx --yes sello dev
npx --yes sello emit-demo
npx --yes sello actions
```

## Pull Requests

- Keep changes small enough to review in one sitting.
- Add or update tests for behavior changes.
- Keep self-hosting first-class. `sello.build` should remain optional convenience, not a protocol requirement.
- Keep service emission separate from owner viewing. The service process should not need the owner private key.
- Do not claim production guarantees for deferred work such as live Rekor proof verification, durable queues, hosted dashboards, managed signing, or production identity operations.
- For protocol changes, cite the affected `SPEC.md` section and include the tradeoff you are making.

## Security And Protocol Review

Public design review is welcome when the issue can be discussed safely. For sensitive reports, see [SECURITY.md](SECURITY.md).
