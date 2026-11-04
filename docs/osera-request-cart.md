# Patch request drafts

Choose **Request drafts** or **Draft patch request** in a library's details. The workflow is **select a library → review existing fixes → explain missing coverage → download a draft**. Package identity, installed version and CVEs are prefilled when starting from a library. The editor puts the rationale and existing-fix explanation first; package URL, scope precision, version and advisory identifiers are under Advanced. Manual entry is available explicitly.

Drafts are stored in this browser, separately for each dataset. Library filters and upgrade-class chips are hidden because they do not filter drafts. **Upgrade recipes** is the separate OpenRewrite workflow. No action in Request drafts submits to OSERA.

Review the readable draft before choosing **Download request draft**. JSON is an optional technical export. Share the downloaded file through your agreed request channel; no intake service is connected. Unsaved editor changes must be saved before download review, and changing the form invalidates the preview.

The saved patch-adoption evaluation from #69 can populate this same workflow through **Draft requests for coverage gaps** when its snapshot ID matches the dataset scope. The bundled four-application demonstration belongs to a separate snapshot, so its request action is disabled and its demand remains inspectable as snapshot evidence. Browser feed refresh does not recompute a saved evaluation.

## Existing patches and work

The cart uses the enabled catalogs from Patch inventory (#41). Hidden enabled sources still participate in coverage checks; hiding a source only hides its evidence details. Disabling a source removes it from coverage checks. Startup refresh and source changes recalculate coverage while preserving an in-progress edit. Exact-version applicable fixes and exact patched-artifact observations reduce remaining requested advisories. A published OSERA VEX product with no source compatibility mapping is flagged as a candidate for review; it cannot automatically suppress a request for an older version. A request fully covered by an applicable fix requires an incompatibility explanation before export. Partial coverage exports the remaining advisories. An exact example artifact never establishes coverage for every version in a minor or major line.

Patch inventory currently loads released patch evidence, not live OSERA production requests. You can optionally import work references using:

```json
{
  "schema_version": 1,
  "requests": [{
    "identity": "pkg:maven/org.example/core@1.2.3",
    "precision": "exact",
    "line": "1.2.3",
    "advisories": ["CVE-2026-12345"],
    "remediation": ["backpatch"],
    "status": "in_progress",
    "url": "https://github.com/example/backlog/issues/1"
  }]
}
```

Supported work statuses are `requested`, `in_progress`, and `covered`. These are imported source claims with work links, not deployment states. The cart explicitly reports that existing requests are unknown when no work snapshot is loaded. Work matching is exact package + scope precision + line with advisory overlap; cross-line aggregation and co-release grouping are not inferred.

The cart highlights the latest published target for the current baseline and, when present, a later patch in the same minor line. Historical and other-line evidence remains collapsed for inspection. Candidate targets still require applicability review. Feed refresh status is visible and export review is paused while refresh is running.

## Review and export

Select **Review draft for download** to inspect the readable summary and optional exact JSON before downloading. The proposed local v1 contract is:

```json
{
  "schema_version": 1,
  "kind": "osera-coverage-request",
  "requests": [{
    "package": "pkg:maven/org.example/core",
    "scope": { "precision": "exact", "value": "1.2.3" },
    "advisories": ["CVE-2026-12345"],
    "acceptable_remediation": ["backpatch"]
  }]
}
```

Optional `rationale` and `incompatibility` fields contain user-written text. Review them for sensitive details. The export uses an explicit field allowlist; it does not include application names, owners, paths, contracts, local impact counts, the estate scope name or unselected inventory. A download only records a local export timestamp. There is no automatic transmission or implied acknowledgment by OSERA.

This is the initial UI implementation for #42 and a proposed local contract for #29, not an approved OSERA intake API. Live submission, authenticated demand deduplication, richer workflow acknowledgment, co-release grouping and a production backlog adapter remain follow-up work. #42 remains open for those requirements. Existing OpenRewrite YAML generation continues unchanged.
