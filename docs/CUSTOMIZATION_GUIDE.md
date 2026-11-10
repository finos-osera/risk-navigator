# Risk Navigator Customization Guide (Company Overlay)

This guide explains how companies can customize Risk Navigator while staying aligned with upstream spec and UI behavior.

## Goals

- Keep the viewer and dataset contract stable.
- Replace input connectors with company-specific data sources.
- Add enterprise metadata (owners, maintainers, org hierarchy) for better prioritization.
- Maintain a local build that can track upstream updates safely.

## 1. Data responsibilities

Each company should supply:

- Project inventory (service/app/repo identifiers, project refs, releases).
- Dependency edges per project (direct vs transitive).
- CVE mapping source:
  - external (OSV + KEV + EPSS), or
  - internal merged catalog (if your security platform already unifies these).

The output requirement does not change:

- Build `data/<scope>.json` compatible with the schema in `SPEC.md` section 4.1.

If this contract is preserved, the site behavior remains largely the same.

## 2. Custom enrichments (recommended)

Add fields and joins that improve enterprise actionability:

- owner and maintainer identities,
- department / BU / platform team mappings,
- org-chart hierarchy keys,
- criticality and regulatory tags,
- internal ticketing IDs or application portfolio IDs.

These should enrich filtering and reporting without breaking base fields used by the UI.

Project grouping guidance:

- Default/demo behavior should use neutral heuristic grouping (not implied org departments).
- Enterprise overlays should map projects to true org structures (department/BU/platform) and set grouping mode accordingly.

## 3. Pipeline adaptation strategy

Keep the same high-level phases:

1. Ingest vulnerability intelligence.
2. Ingest org/project/dependency graph.
3. Join + normalize to Risk Navigator schema.
4. Validate and publish dataset(s).

You may fully replace extract/ingest adapters, but keep the join output contract stable.

## 4. Overlay repository model (recommended)

Use an overlay repo with upstream as a submodule.

- Upstream submodule: this Risk Navigator project.
- Overlay repo: internal adapters, environment config, secrets handling, CI wrappers, deployment automation.
- Pin a known upstream commit/spec version.
- Upgrade upstream intentionally and run schema/visual regression checks.

This mirrors proven FINOS overlay patterns used in TraderX customization.

Recommended agent workflow:

1. Point your LLM coding agent at this upstream repository.
2. Give it your inventory, SBOM, vulnerability, ownership, and environment requirements.
3. Instruct it to create a separate customization overlay repository rather than modifying upstream directly.
4. Keep company-specific adapters, credentials, deployment config, and metadata mappings in the overlay.
5. Keep the final output contract unchanged: the overlay should still build `data/<scope>.json` files compatible with `SPEC.md` section 4.1.

A useful starter instruction is:

```text
Use this Risk Navigator repository as the upstream reference. Create a company
customization overlay that preserves the viewer and dataset contract, replaces
the extractor inputs with our internal inventory/SBOM/vulnerability sources,
adds our ownership metadata, and documents the build and validation pipeline.
Do not put secrets or local workstation paths in upstream files or published
dataset metadata.
```

Reference architecture guidance:

- [Customizing TraderX](https://finos.github.io/traderX/docs/spec-kit/customizing-traderx)
- [Custom Overlay Architecture](https://finos.github.io/traderX/docs/spec-kit/custom-overlay-architecture)
- [Custom Environments Guide](https://finos.github.io/traderX/docs/spec-kit/custom-environments-guide)

## 5. Suggested overlay layout

```text
your-company-risk-nav-overlay/
  upstream/
    risk-nav/                 # git submodule pinned to upstream commit
  adapters/
    extract_from_internal_cmdb.py
    extract_dependency_edges.py
    ingest_internal_vuln_feed.py
  config/
    environments/
      dev.yaml
      prod.yaml
  pipelines/
    build_scope.sh
    refresh_external_signals.sh
  tests/
    test_schema_contract.py
    test_company_enrichments.py
```

## 6. Versioning and upgrade discipline

- Record the upstream commit SHA and spec version used by each release.
- Keep a changelog of local customizations.
- On upstream update:
  1. bump submodule,
  2. rerun pipeline,
  3. validate schema contract,
  4. validate UI workflows (filters/modes/top-fixes/cart/help docs).

### 6.1 Application version-ordering policy for estate imports (`REL-003-JAVA` and explicit conventions)

When `scripts/estate_import.py` merges multi-version application observations and evaluates the optional `latest_production_version` view, it applies an explicit convention-aware ordering policy (`APPLICATION_VERSION_ORDERING_POLICY`):

1. **Explicit or reliably established application convention (`version_convention`)**:
   - Callers may declare the application's version convention via `osera:version_convention` (CycloneDX property, SPDX `creationInfo.comment` key, or inventory feed `version_convention` / `version_scheme` field) using `maven` (`java`, `rel-003-java`), `semver`, `calver`, or `unsupported` (`opaque`, `git-sha`).
   - When not explicitly set, the convention is inferred only from the application's own root artifact PURL (`pkg:maven/...` -> `maven`; `pkg:npm/...`, `pkg:pypi/...`, `pkg:cargo/...`, `pkg:golang/...`, `pkg:nuget/...` -> `semver`) or unambiguous application version tokens such as `-osera-NNNNN` or `.Final` / `.RELEASE` / `.GA` (`maven`).
   - **Never inferred from consumed dependencies**: Consuming Java/Maven library dependencies does not cause an application to be treated as using Maven version ordering.
2. **Java / Maven and `REL-003-JAVA` patch ordering (`convention = "maven"`)**:
   - Separates the baseline release qualifier (`.Final`, `.RELEASE`, `.GA`, `.vYYYYMMDD`, or prerelease `-alpha` / `-beta` / `-M1` / `-RC1` / `-CR1` / `-SNAPSHOT`) from post-release patch suffixes (`-osera-NNNNN`, `-sp`, `-post`, `-patch`), ensuring:
     - Numeric-base OSERA patch: `5.3.39 < 5.3.39.1-osera-00001`.
     - Qualified OSERA patches: `5.6.15.Final < 5.6.15.Final-osera-00001` and `2.0.0.RELEASE < 2.0.0.RELEASE-osera-00001`.
     - Patch sequence: `...-osera-00001 < ...-osera-00002`.
     - Genuine prereleases remain below the baseline release (`5.6.15.CR1 < 5.6.15.Final < 5.6.15.Final-osera-00001`, `2.0.0-RC1 < 2.0.0`).
     - Numeric hyphen build/patch revisions rank after the base release (`2.0.0 < 2.0.0-1 < 2.0.0-2`).
3. **SemVer ordering (`convention = "semver"`)**:
   - Numeric hyphen suffixes without an explicit `maven` convention follow SemVer prerelease precedence (`2.0.0-1 < 2.0.0`, `2.0.0-rc.1 < 2.0.0`), while explicit `-osera-NNNNN` post-release patches still order above their unpatched baseline.
4. **Honest handling of ambiguous or unsupported version schemes**:
   - If an application has multiple active versions with convention-sensitive tokens (such as `2.0.0` and `2.0.0-1`) without an explicit convention or root PURL, carries conflicting conventions/root PURLs across imports (`version_ordering_status = "ambiguous_convention"`), or uses non-orderable version strings such as opaque git SHAs or branch names (`version_ordering_status = "unsupported_scheme"`), `latest_production_version` is set to `""` rather than guessing, and the `latest_production_version` view retains all active production releases for that application (`latest_version_selection_status = "partial_ambiguous_or_unsupported"`).
   - Underlying supplied inventory (`all_active_production`, `all_active_deployments`, `all_imported`) is never discarded by latest-version selection.

## 7. Minimum acceptance checklist

- Dataset validates against schema contract.
- Direct/transitive counts are correct and consistent.
- Project references and ownership mappings render correctly.
- Top fixes and detail panes still produce readable/structured output.
- OpenRewrite cart behavior is clear (direct dependencies in current iteration).
- If the OpenRewrite package prefix is customized, generated recipe IDs still
  use Java-safe `A-Za-z0-9_` class-style segments and contain no hyphens.
