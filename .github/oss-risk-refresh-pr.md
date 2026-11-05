Refreshes the FINOS OSERA `backpatch-*` library seed inventory and collected OSS-risk scorecards from live public evidence sources (`https://feed.finos.org/openvex.json`, OSV, CISA KEV, OpenSSF Scorecard, `deps.dev`, npm downloads, and the GitHub API).

All upstream HTTP and API responses are fetched with explicit cache bypass (`--refresh`), and each evidence block retains its source `observed_at` / `retrieved_at` timestamps and OSERA OpenVEX `feed_version` / `feed_last_updated` provenance.

Only validated JSON datasets (`oss-risk/data/finos-osera-backpatch-libraries.json`, `oss-risk/data/finos-osera-backpatch-scorecards.json`, and `oss-risk/data/collected-library-scorecards.json`, each bounded to a 5 MiB distribution limit) are committed; transient staging files and HTTP response caches stay out of Git.

Validation: staged fail-closed schema/provenance/rate-limit checks (`npm run validate:oss-risk`), Python test suite (`pytest -q`), and Docusaurus static build (`npm run docs:build`). Review changes in backpatch discovery, OpenVEX patch coverage, and vitality/security scores before merging.
