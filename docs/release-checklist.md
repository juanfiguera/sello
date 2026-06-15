# Release Checklist

Use this checklist before publishing a Sello release.

## Preflight

- Confirm `git status --short` is clean.
- Confirm `node -v` is `v22.7.0` or newer.
- If multiple Node versions are installed, confirm `PATH` resolves `node` to Node 22.7 or newer before running package scripts.
- Confirm `package.json` has the intended version.
- Confirm `sdks/python/pyproject.toml` has the intended version when publishing Python.
- Confirm `README.md` and `docs/sdk-quickstart.md` match the current CLI and examples.
- Confirm the paper link and local PDF are current, if the paper changed.

## Local Verification

```bash
node --run test
npm pack --dry-run
```

Fresh clone smoke test:

```bash
tmpdir=$(mktemp -d)
git clone https://github.com/juanfiguera/sello.git "$tmpdir/sello"
cd "$tmpdir/sello"
node -v # must be v22.7.0 or newer
node --run test
node --run package:test
npm pack --dry-run
node --experimental-strip-types sdks/typescript/src/cli/sello.ts --help
node --experimental-strip-types sdks/typescript/src/cli/sello.ts dev --dry-run
```

## npm Verification

```bash
npm whoami
npm view sello version
npm publish --dry-run
```

If the package name is already published, confirm the local version is greater than the registry version before publishing.

## PyPI Verification

```bash
python -m pip install --upgrade build twine
cd sdks/python
rm -rf dist
python -m build
python -m twine check dist/*
```

The PyPI project uses trusted publishing from `.github/workflows/release.yml`.

## Publish

```bash
npm publish
git tag v$(node -p "require('./package.json').version")
git push origin main --tags
```

After publishing:

- Confirm `npm view sello version` shows the new version.
- Confirm `python -m pip index versions sello` shows the new version after PyPI publishing.
- Confirm `npx sello --help` works from a clean temp directory.
- Confirm GitHub Actions passes on `main`.
