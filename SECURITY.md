# Security Policy

## Supported Versions

The latest published `0.x` release receives security fixes.

| Version | Supported |
| ------- | --------- |
| 0.1.x   | ✅        |

## Reporting a Vulnerability

Please report security vulnerabilities **privately** — do not open a public
issue.

- Email **cbsshekhawat18@gmail.com** with a description of the issue, and
- Use GitHub's [private vulnerability reporting](https://github.com/cbsshekhawat18-lab/indian-pii/security/advisories/new)
  if you prefer.

Include, where possible:

- A clear description of the vulnerability and its impact.
- Steps to reproduce (a minimal code snippet or input string is ideal).
- The package version and runtime (Node version / browser).

You can expect an acknowledgement within a few days. Once a fix is ready, a
patched version will be published to npm and the advisory disclosed.

## Scope note

`indian-pii` performs **format and checksum validation only**. A value passing
`validate()` is well-formed but is not proof that an identifier is real, issued,
or active. Treating detection results as proof of identity is a misuse, not a
vulnerability — see the "Honest limitations" section of the README.
