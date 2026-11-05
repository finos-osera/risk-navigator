# Refreshing the FINOS sample

Run `npm run refresh:finos` with authenticated GitHub access (`gh auth login` or `GH_TOKEN`). This refreshes the existing **FINOS GitHub Org Snapshot** in the selector. The small curated SBOM and OSERA walkthrough datasets remain labelled demos.

The refresh lists public active non-fork FINOS repositories and reads files at a recorded commit. Root manifests are prioritised, with at most 32 manifests per repository. It also reads up to four npm v2/v3 lockfiles in each selected repository: architecture-as-code, FDC3, legend-studio, open-resource-broker, perspective, symphony-bdk-java, traderX and waltz. Repositories without these lockfiles retain manifest coverage. It follows runtime, optional and installed peer dependency edges, preserves nested versions and parent relationships, and excludes dev-only dependency graphs. No repository code or install scripts execute.

The snapshot combines those observations with a fresh official OSV dump filtered to observed packages, exact-version OSV API queries (including advisories that specify ranges without enumerating versions), CISA KEV, FIRST EPSS and deps.dev release dates. Failed vulnerability/signal downloads stop publication rather than substituting synthetic demo signals. `data/finos-coverage.json` records the repository commits, scan times, limits, failures, resolved lockfiles and coverage totals. The app's **About Data Sources** view shows separate inventory, vulnerability and signal timestamps.

## Keep Git small

Only these generated artifacts are published:

- `data/finos-github-org.json`: compact app data, capped at **5 MiB**.
- `data/finos-coverage.json`: coverage and provenance, capped at **256 KiB**.
- The matching entry in `tool/manifest.json`.

Publication validates the schema and byte limits before replacing the existing snapshot. CI also checks the size budget. Raw CSVs, vulnerability archives (which can be multiple gigabytes), SQLite databases, advisory descriptions and caches remain ignored under `data/local/`. The previous committed FINOS raw CSV copies are removed to avoid duplicating the distributable data. Synthetic demo fixtures remain in Git.

The `version_chains` dictionary stores each full package version history once; library rows reference it using `version_chain_ref`. The app expands these references on load, preserving the complete history without duplicating it for every observed version.

The published `dependency_inventory` retains all extracted package versions and relationships, including those without a matched CVE. Its `libraries` and `projects` arrays are dictionaries; `edge_columns` describes indexed rows of `[project, library, direct, qualifier, parent]`, with `null` for no parent. This is input for future inventory-wide patch analysis; it does not itself prove patch deployment. Existing library views continue to focus on vulnerable dependencies. Long advisory descriptions are omitted and summaries limited to 500 characters; CVE IDs link to authoritative details in the app.

## Coverage is partial

Declared version ranges use the existing manifest parser's approximation; resolved lockfiles are stronger evidence. This is not a complete build-resolved SBOM or an inventory of deployed applications. Maven/Gradle inherited versions, Yarn/pnpm/Python lockfiles, build profiles, and container contents need further work. Optional packages may not install on every platform. The viewer is CVE-based, so advisories without CVE aliases are not included as CVE findings. A repository with no extracted dependencies is **unknown**, not clean. Repository rows explicitly flag manifest/lockfile limits and truncated trees. Partial file failures stay visible; whole repository failures block publication.

## Repeatable updates

`.github/workflows/refresh-finos.yml` runs weekly and can be dispatched manually. It refreshes the sample, runs tests and opens or updates a separate review PR. It never merges automatically. GitHub's repository setting allowing Actions to create pull requests must be enabled. The workflow uses the built-in token; GitHub may suppress downstream workflows triggered by that token, so the refresh job runs its own Python checks and reviewers should run any required additional checks before merging.

For interrupted local runs, `--reuse-inventory` resumes from the recorded local scan. `--reuse-vulnerabilities` also reuses the local vulnerability DB and is for manual recovery only. Neither changes the original evidence timestamps. Scheduled runs always perform a full refresh.
