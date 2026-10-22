# Patch feeds and observed estate coverage

Select **Patch coverage** beside Libraries. This mode uses the normal table and right-hand details pane, with one row per library/version and consumer projects in the details. Libraries also has a Patch coverage column. Clicking a row shows targets, addressed and residual findings, and source evidence. The existing risk-planning indicator is named **Patch needed** to distinguish demand from published coverage.

The main filters apply to both views. The coverage Show selector can narrow to opportunities or a state. Coverage totals use the library filters and scoped project observations; the Show selector narrows rows without changing totals. Filters collapse on entry to Patch coverage and can be expanded again.

OSERA refreshes automatically in the background at startup. Saved evidence is displayed immediately; a timeout or version mismatch keeps the last valid snapshot with an error/stale indication. No estate inventory is transmitted. Turn startup refresh off in Manage sources for offline usage.

**Manage sources** supports supplemental company inventories via JSON upload or HTTPS URL, custom source names, refresh, removal, and separate controls:

- **Enabled** controls participation in matching, conflicts and aggregate coverage.
- **Visible** controls provider badges and target evidence. Hidden enabled sources still contribute to totals; their presence is labeled rather than incorrectly attributed to a visible provider.

Each inventory needs a stable unique feed ID; multiple inventories from a provider use different IDs. Reimporting a feed preserves its name, enabled state and visibility. Imported sources are local browser data. URL sources are fetched only on explicit add/refresh; OSERA is the only automatic source. File sources are updated by reimporting the file.

**Refresh OSERA** reads `https://feed.finos.org/openvex.json` and `https://feed.finos.org/sets.json` together. Matching feed versions are required. The adapter was checked against feed version 21 on 20 October 2026; a minimal real excerpt is retained in `tests/fixtures/osera-feed-excerpt.json`. Community #39 was unavailable; these live published documents are the verified integration reference.

An OpenVEX fixed statement identifies an exact product/advisory assertion, not compatibility with older versions. The view requires an OSERA release set to be “in the feed” before treating that artifact as published. Held, missing, conflicting and non-fixed evidence remains visible but cannot count as an available patch. A raw OpenVEX import without release-set evidence remains unconfirmed. For offline use, import `{ "openvex": <document>, "release_sets": <sets document> }`.

Published fixes matching a component and advisory are **candidates** until explicit source-version applicability is provided. We do not infer applicability by stripping `-osera-…`, by matching a minor version, or by assuming every companion artifact fixes the same CVE. Inspect the target details for release-set members, supplier, advisory aliases and provenance.

Other providers can use this versioned catalog (all values below are illustrative):

```json
{
  "schema_version": 1,
  "id": "member-example",
  "provider": "Member-supplied example",
  "generated_at": "2026-10-20T00:00:00Z",
  "patches": [{
    "id": "core-fix-1",
    "target": "pkg:maven/org.example/core@1.2.3-patch1",
    "source_versions": ["1.2.3"],
    "advisories": ["CVE-EXAMPLE"],
    "aliases": [["CVE-EXAMPLE", "GHSA-EXAMPLE"]],
    "state": "released",
    "evidence": "https://example.org/releases/core-fix-1"
  }]
}
```

`source_package` may specify a versionless package URL if the replacement has different coordinates. `source_versions` is an explicit list of versions, not a range expression; an empty list leaves applicability unknown. States are `released`, `planned`, `withdrawn`, or `superseded`. Optional companion, evidence, and supersession metadata are retained in the details. Importing the same feed ID replaces the previous snapshot. Feeds can be disabled or removed and are stored only in this browser. HTTPS URL imports require the server to allow browser access (CORS); file imports work offline. No inventory is sent to a feed server.

## Reading the metrics

A component instance is a unique application + exact package/version observation. Repeated graph paths, advisory aliases and overlapping feeds do not add instances. Application denominators include all applications recorded in the chosen dataset/application scope. State filtering changes rows, not totals. Main library and project filters scope the analysis. Disabling a source changes matching; hiding it does not.

- **Applicable patches** require explicit source-version applicability and a released, fixed record.
- **Observed use** requires the exact target package/version (including qualifiers where supplied) in the inventory. It is not deployment verification.
- **Patched / eligible instances** includes observations with an applicable fix or an observed target; no eligible instances displays N/A.
- **Published candidates** are useful review opportunities, but excluded from confirmed applicability/adoption totals.

Current generated datasets largely contain vulnerable libraries and may truncate consumers/findings. Missing non-vulnerable patched components make observed adoption a lower bound. The view labels partial inventories and source dates. Do not interpret zero observations as zero real adoption. Complete datasets may set `meta.inventory_complete: true` only when their `libraries` and `consumer_projects` contain the full observed inventory. Residual findings are retained when a patch addresses only part of a component's advisories.

## Initial scope

This is a first delivery slice of #41. It supports exact package identities and explicit version lists, not automatic compatibility decisions, entitlement checks, range evaluation, signature verification, deployment verification or a full SBOM importer. Live backlog intake and provider-specific policy gates remain separate work. Do not automatically close #41: broader inventory ingestion, freshness policy, and the remaining acceptance criteria require follow-up.

Run `npm run test:patches` for the deterministic feed/matching tests and `npm run docs:build` to verify both published tool paths carry the modules.
