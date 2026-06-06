# Release Checklist

Use this checklist before publishing a Sello npm release.

## Preflight

- Confirm `git status --short` is clean.
- Confirm `node -v` is `v24.0.0` or newer.
- If multiple Node versions are installed, confirm `PATH` resolves `node` to Node 24 before running package scripts.
- Confirm `package.json` has the intended version.
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
node -v # must be v24.0.0 or newer
node --run test
npm pack --dry-run
node --experimental-strip-types src/cli/sello.ts --help
node --experimental-strip-types src/cli/sello.ts dev --dry-run
```

## npm Verification

```bash
npm whoami
npm view sello version
npm publish --dry-run
```

If the package name is already published, confirm the local version is greater than the registry version before publishing.

## Publish

```bash
npm publish
git tag v$(node -p "require('./package.json').version")
git push origin main --tags
```

After publishing:

- Confirm `npm view sello version` shows the new version.
- Confirm `npx sello --help` works from a clean temp directory.
- Confirm GitHub Actions passes on `main`.
