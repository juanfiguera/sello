# Sello SDKs

The protocol, paper, and project docs live at the repository root. Language SDKs live here:

- [`typescript/`](typescript/): npm package source, CLI, examples, fixtures, and Node tests.
- [`python/`](python/): Python package source and tests.

Root commands still work from the repository top level:

```bash
node --run test
node --run package:test
python -m pip install ./sdks/python
python -m unittest discover -s sdks/python/tests
```

This keeps the first screen of the repo focused on the protocol while giving each language a predictable home.
