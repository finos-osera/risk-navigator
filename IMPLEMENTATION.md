# Risk Navigator Implementation Notes

## What was implemented

A complete v0 implementation now exists under this folder:

- `scripts/ingest_vulns.py` - ingests OSV-style advisories into `data/vulns.db` (SQLite).
- `scripts/fetch_external.py` - fetches/normalizes CISA KEV + FIRST EPSS into `data/external/{kev,epss}.json`.
- `scripts/extract_org.py` - generates the six required raw CSV extracts for a sample organizational scope (UI label: `OSERA Demo Data (Example)`, slug: `finos-sample-platform`), supports importing CycloneDX SBOM folders, and supports a live FINOS GitHub-org extractor (`--source finos-github`) that writes an offline snapshot.
- `scripts/build_dataset.py` - joins raw CSV + KEV + EPSS into `data/<scope>.json` matching the contract.
- `scripts/validate_dataset.py` - schema validator for built datasets.
- `tool/risk-navigator.html` - single self-contained HTML/JS/CSS app with all six modes, filters, details, simulators, theme, and Maven cart/YAML/prompt workflow.
- `tool/manifest.json` - dataset list for selector.
- `tests/` - safe-version logic + schema validation tests.

## Architecture decisions

1. Static viewer contract first
- Chosen architecture follows the spec contract boundary: pipeline emits `scope.json`; UI is stateless and reads it directly.
- This keeps data prep (private org context) decoupled from visualization and decision tooling (open source).

2. SQLite for vuln normalization
- `ingest_vulns.py` uses only Python stdlib and stores normalized vulnerability/package/version rows in SQLite.
- Fast enough for local sample runs and straightforward to query from follow-on scripts.

3. External signal isolation
- KEV/EPSS are fetched into dedicated files under `data/external/` and joined later.
- This cleanly supports independent refresh cadence and cached/offline behavior.

4. Raw CSV audit layer
- `extract_org.py` persists all six raw files under `data/raw/<scope>/` before join.
- This makes audits and analyst review easy in spreadsheet/notebook tooling.

5. Safe-version walker implementation
- `scripts/common.py` implements GA-only filtering and nearest-safe-version selection logic.
- Non-GA/rebuild/prerelease suffixes are excluded from target suggestions.

6. UI: single-file vanilla JS
- Kept as one static file with no bundler dependency at runtime to match portability requirements.
- Vite is used only as an optional local static server.

7. Performance-oriented rendering
- In-memory dataset cache for manifest switching.
- Debounced filter re-render for text/slider/epss fields.
- Row selection updates detail pane without full dataset reload.

8. Parallel GitHub extraction for real org dataset
- `extract_org.py --source finos-github` pulls the live FINOS repo list from GitHub and fetches manifests in parallel with a thread pool (`--github-parallelism`).
- It scans common manifest formats (`pom.xml`, Gradle, `package.json`, `requirements.txt`, `pyproject.toml`, Dockerfiles) and normalizes direct dependencies into the same raw edge schema.
- Output is still the same six CSV contract under `data/raw/<scope>/`, so no downstream code changes are required.

9. Targeted OSV ingestion for speed
- A package allowlist can be generated from the scope dependency graph (`scripts/build_package_allowlist.py`).
- `ingest_vulns.py --package-allowlist-file ...` then ingests only OSV records that affect those package keys, reducing DB size and rebuild time for scope-specific refreshes.
- Ingest now has fingerprint-based cache reuse: if OSV source + filter inputs are unchanged, it skips re-ingest and reuses the existing SQLite DB.

## Sample data strategy

- A realistic FINOS-like sample organizational portfolio is checked in via generated raw extracts and built dataset.
- Sample includes multi-team projects, direct + transitive dependencies, vulnerable libraries, amplifiers, and framework clusters.
- Live FINOS-org rebuild artifacts are intended to be local-only pipeline outputs (gitignored) because they are easy to recreate and may change frequently.
- Full OSV source dumps are stored in local cache only (`data/local/osv/all.zip`, gitignored).
- For real organizations:
  1. Use CycloneDX/SPDX/Syft or build-tool exports to generate project dependency edges.
  2. Keep the same six raw CSV file shapes.
  3. Re-run `build_dataset.py` unchanged.

## About FINOS + SBOM coverage

The sample portfolio uses FINOS-style project naming and common OSS libraries with known vulnerability patterns. For production-quality FINOS analysis, the recommended path is:

1. Enumerate FINOS repositories.
2. Generate per-repo CycloneDX SBOMs (for example with Syft).
3. Run `extract_org.py --source cyclonedx --sbom-dir <dir>` as the extract phase.
4. Build/join with the same pipeline.

This keeps the implementation reproducible even when public repository metadata or dependency manifests change over time.

## Commands

From `risk-navigator`:

```bash
npm install
npm run build:all
npm run build:all:finos-org
npm test
npm run dev
```

Then open `/tool/risk-navigator.html` via Vite (or any static file server).

### Excluding dependency classes from a scope build

If you want to exclude non-target dependency classes (for example PyPI or base-image/RPM dependencies), use:

```bash
python3 scripts/build_dataset.py \
  --scope finos-sample-platform \
  --exclude-library-namespaces pypi,rpm,oci,docker
```

The exclusion list is recorded in `meta.filters_applied.library_namespaces_excluded` in the built dataset.
