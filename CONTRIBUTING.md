# Contributing to indian-pii

Thanks for your interest in improving **indian-pii**. Contributions of all kinds
are welcome — bug reports, new detectors, better validation, docs, and tests.

## Ground rules

- **Zero runtime dependencies.** The library must stay dependency-free. Dev
  dependencies (build/test tooling) are fine.
- **Real validation only.** Detectors validate by checksum or strict structure —
  never a shape-only re-test of the regex.
- **Tests are required.** Every detector change must add or update tests covering
  **valid and invalid** cases (wrong checksum, wrong structure, value embedded in
  a longer string, and empty/`null` input).
- **Browser + Node.** Don't use APIs unavailable in one of those environments.
- **ReDoS safety.** Keep regexes linear with bounded quantifiers; avoid
  catastrophic backtracking.

## Development setup

```bash
git clone https://github.com/cbsshekhawat18-lab/indian-pii.git
cd indian-pii
npm install
```

Common scripts:

```bash
npm test          # run the full Vitest suite
npm run typecheck # tsc --noEmit
npm run build     # produce dist/ (ESM + CJS + .d.ts)
```

Before opening a pull request, make sure **`npm test` and `npm run typecheck`
both pass.**

## Adding or changing a detector

1. Add/edit the detector in `src/detectors/` (it must export the uniform
   `{ id, label, category, severity, regex, validate, mask, contextHints }`
   shape).
2. Register it in `src/detectors/index.ts` if it's new.
3. Add tests in `test/` (≥3 valid, ≥3 invalid).
4. Update the detector table and per-detector section in `README.md`.
5. Note the change in `CHANGELOG.md`.

## Commit & PR guidelines

- Keep commits focused and write clear, imperative messages
  (e.g. `fix: allow spaces inside mobile numbers`).
- Describe the change and the reasoning in the PR. Link any related issue.
- Be patient and respectful in review — see the
  [Code of Conduct](./CODE_OF_CONDUCT.md).

## Reporting security issues

Please **do not** open a public issue for security problems. See
[SECURITY.md](./SECURITY.md) for private disclosure instructions.

## License

By contributing, you agree that your contributions will be licensed under the
[MIT License](./LICENSE).
