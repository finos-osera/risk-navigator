# OSERA patch request cart

The OSERA cart is independent of the Maven OpenRewrite cart. Choose **Request missing coverage** in the library details pane from Libraries or Patch coverage. This opens the **Patch requests** mode, which also supports manual entry. The cart is no longer embedded in the removed bottom coverage drawer. Its requests belong to the selected dataset and are independent of display filters.

Requests are stored locally per dataset scope. Repeated adds merge advisory coverage for the same package and line; different versions/line precision stay distinct. Direct/transitive impacts are local observations with shared applications deduplicated. Those application counts can overlap and are not proof of deployment or predicted risk-score reduction.

## Existing patches and work

The cart uses the enabled catalogs from the coverage view (#41). Hidden enabled sources still participate in coverage checks; hiding a source only hides its evidence details. Disabling a source removes it from coverage checks. Startup refresh and source changes recalculate coverage while preserving an in-progress edit. Exact-version applicable fixes and exact patched-artifact observations reduce remaining requested advisories. A published OSERA VEX product with no source compatibility mapping is flagged as a candidate for review; it cannot automatically suppress a request for an older version. A request fully covered by an applicable fix requires an incompatibility explanation before export. Partial coverage exports the remaining advisories. An exact example artifact never establishes coverage for every version in a minor or major line.

The coverage view currently loads released patch evidence, not live OSERA production requests. You can optionally import work references using:

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

## Review and export

Select **Review export** to inspect the exact JSON and human-readable summary before downloading. The proposed local v1 contract is:

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
