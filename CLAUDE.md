# Sello — Agent Instructions

Sello is a protocol for independently-verifiable records of AI agent actions. The spec lives in `SPEC.md`; the reference implementation is in `src/`.

## Project Conventions

- TypeScript reference implementation uses Node 22.7+ with `--experimental-strip-types` (see `package.json`).
- Tests use Node's built-in test runner. Run with `node --run test`.
- Local demo and benchmark are at `src/cli/demo.ts` and `src/cli/bench.ts`.
- The spec is the source of truth. Implementation changes that affect wire format must update `SPEC.md` first.
- Apache 2.0 license. New files do not need a per-file header.

## Skill routing

When the user's request matches an available skill, invoke it via the Skill tool. When in doubt, invoke the skill.

Key routing rules:
- Product ideas/brainstorming → invoke /office-hours
- Strategy/scope → invoke /plan-ceo-review
- Architecture → invoke /plan-eng-review
- Design system/plan review → invoke /design-consultation or /plan-design-review
- Full review pipeline → invoke /autoplan
- Bugs/errors → invoke /investigate
- QA/testing site behavior → invoke /qa or /qa-only
- Code review/diff check → invoke /review
- Visual polish → invoke /design-review
- Ship/deploy/PR → invoke /ship or /land-and-deploy
- Save progress → invoke /context-save
- Resume context → invoke /context-restore
