# Dependency security status

Reviewed on 2026-10-04 using `npm audit` for both lockfiles.

The root project has no reported vulnerabilities. The website has no critical
findings; its 29 high entries all originate from the single unresolved `braces`
advisory below, including packages that depend on it. Two moderate entries remain
from the `uuid` advisory GHSA-w5hq-g745-h8pq and its dependent package.

## Unresolved upstream issue: braces

- Advisory: [GHSA-vfj7-8cjw-p6xm](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm)
- Installed version: `braces@3.0.3`.
- Upstream lists no patched version as of this review.
- Deeply nested brace patterns can exhaust the JavaScript call stack.
- The dependency is used by Docusaurus build and development tooling through
  glob matching and file watching (`micromatch`, `fast-glob`, and `chokidar`).
  The deployed site is static; this review does not establish that every
  development-server input is unreachable by an attacker.

This issue remains unresolved by explicit maintainer decision rather than adding
a locally maintained patch. It has not been suppressed or marked fixed. Keep
development servers restricted to trusted access and avoid untrusted glob
configuration. Revisit when an upstream patch or compatible dependency replacement
is available; update the lockfile and rerun the website build and audit.

## serialize-javascript override

The website overrides `serialize-javascript` to `^7.1.2` because the Docusaurus
webpack plugins still request the vulnerable 6.x line. This addresses
[GHSA-5c6j-r48x-rmvq](https://github.com/advisories/GHSA-5c6j-r48x-rmvq) and
GHSA-qj8w-gfj5-8c6v. The replacement supports the configured Node 24 runtime.
Remove the override once all consuming plugins require a patched version.

## Rechecking

From the repository root:

```sh
npm ci
npm audit
npm ci --prefix website
npm audit --prefix website
npm run docs:build
npm test
```

The website audit currently exits nonzero because the findings above remain open.
