# Browsing published patches

Patch inventory opens **Browse patches**, a catalog of release cards inspired by OSERA’s package/maintained-line browsing. Each card shows the package, provider, minor line, latest published version, fixed advisory count and estate presence. One latest target per package/provider/minor line is shown; historical builds are omitted. Catalog detail shows published CVEs, release-set members and source evidence.

**Estate relevance** filters by Show everything, Package in my estate, Package outside my estate, Same minor line in my estate, or Exact patch in my estate. Presence matches package identity independently of CVEs and upgrade eligibility. The selected estate scope and its inventory limitations still apply. An absent match in partial inventory is not proof of absence from production.

Catalog browsing does not show upgrade arrows, adoption denominators, effort estimates or an upgrade-scope control. Package presence on a different line is context, not a downgrade or upgrade recommendation. Summary cards describe the whole visible catalog; search and relevance filters narrow displayed cards.

**Estate opportunities**, Ready to adopt, Needs review and Adopted retain the planning workflow below, including latest-only baseline selection and optional broader fallbacks.

# Patch inventory and observed estate coverage

Select **Patch inventory** beside Libraries. Browse Estate patches, Ready to adopt, Needs review, Adopted, or Latest published patches. Each row represents one exact target artifact, combining overlapping feed assertions. A target may appear in both Ready to adopt and Adopted during partial rollout. Search by package, version, advisory or provider. Libraries retains compact coverage badges.

Rows show current → target versions, observed / confirmed eligible component instances, review candidates, affected applications and version-distance effort hints. Zero eligible instances displays N/A. Only the latest suggested target per observed version and provider appears. Distance does not establish compatibility: OSERA records without explicit source-version evidence remain Needs review.

The detail pane includes per-application observations, residual findings for the selected target, release-set artifacts to assess together, and source evidence. **Latest releases · published patch targets** uses the same latest-only selection policy as estate rows. Downgrades and major-version jumps are excluded. This is numeric-aware version-label ordering, not an authoritative release chronology or compatibility ranking. Two-part version lines are supported; older lines are flagged for assessment.

The three summary counts are distinct target counts, not summed CVEs or applications. Latest published patches includes targets outside the selected estate. Main filters scope estate observations, not the global published catalog. Hidden enabled sources contribute to counts but their exclusive targets and evidence are hidden. Partial inventory remains a lower bound on adoption.

The left pane has one scroll surface: navigation, filters, patch controls and rows scroll together, with table column headings staying visible while browsing rows. The right details pane scrolls independently. Libraries keeps patch controls compact; Manage sources exposes timestamps and source settings.

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

## Upgrade scope

The default **Current baseline only** preserves every numeric component of the observed upstream version: `1.33` selects the latest `1.33.*` patch, while `1.2.4` selects the latest `1.2.4.*` or OSERA revision. **Allow later patches in same minor** permits `1.2.10` only when no current-baseline candidate exists. **Allow newer minor as fallback** additionally permits a newer minor within the same major when no closer candidate exists. Numeric segments and OSERA revisions are compared numerically; downgrades, major jumps and unrecognized version syntax are never inferred as suggestions. This policy narrows candidates; it does not prove compatibility.

Previously adopted exact artifacts remain visible as observations, even when a newer target exists. Latest published patches is a separate catalog with one latest target per provider/package/major-minor line; outside-scope targets have no suggested estate upgrade attached.

## Integration with saved evaluations and compact inventory

The browser accepts both its numeric `schema_version: 1` catalog and main's `osera-patch-catalog/v1` provider catalog, either directly or wrapped as `{config, document}`. It maps explicit applicability, release state, per-record provider, evidence links, companions and artifact digests. Conflicting non-null digests across enabled sources block coverage credit. Flat advisory aliases are combined only for a single fixed advisory to avoid merging unrelated CVEs. The browser intentionally does not infer compatibility by stripping an OSERA suffix; saved Python evaluations may apply different rules and are labeled separately.

When `dependency_inventory.schema_version` is 1, package presence and observed adoption also use its indexed project/library edges, including components with no matched CVE. Repeated edges are deduplicated, project scope and direct/transitive selections apply, and placeholder versions are not treated as exact observations. This is backward compatible with existing datasets and ready for #48's compact inventory without merging #48 into this branch. Library risk filters still apply to finding rows; compact package presence is independent of CVE severity. Inventory-only components expose their observations without linking to nonexistent vulnerability details.

Saved evaluation demand enters the draft workflow only for a matching dataset scope. The bundled demonstration fixture cannot become a request against a different estate. This bridge does not make the saved evaluation a live feed or a verified deployment signal.
