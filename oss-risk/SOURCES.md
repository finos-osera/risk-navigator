# OSS Risk Collector Sources

The collector prefers live query APIs for library scorecards. That keeps the
workflow lightweight and avoids downloading full advisory archives unless the
task is broad inventory analysis.

See `PRIOR_ART.md` for how these sources map to mature project-health,
security, SBOM, criticality, and underproduction models.

## Lightweight Sources

| Source | Used for | Collector behavior |
|---|---|---|
| OpenSSF Scorecard API | Security posture checks and scorecard check details | Queries each GitHub repository. |
| GitHub API | Stars, forks, age, push activity, release/tag activity, commit windows | Queries each configured repository. Uses `GITHUB_TOKEN` or `GH_TOKEN` when available. |
| deps.dev API | Package versions, latest/default version, public dependent counts | Queries each configured package where ecosystem is supported. |
| npm downloads API | npm package download trend proxy | Queries npm packages only. |
| OSV query API | Package-level vulnerability records | Queries named packages directly. No full OSV download required. |
| CISA KEV JSON feed | Known-exploited CVE overlay | Downloads the small KEV JSON feed and matches OSV CVE aliases. |
| Risk Navigator collections | Enterprise exposure overlay | Browser loads `tool/manifest.json` and joins selected dataset libraries by package coordinate. |

## OSV Options

For OSS risk scorecards, use:

```bash
npm run collect:oss-risk
```

This calls the OSV query API for the named packages.

For faster non-security collection:

```bash
npm run collect:oss-risk:no-osv
```

For broad Risk Navigator SBOM analysis, the repository already supports full
OSV download and local ingest:

```bash
npm run fetch:osv
npm run ingest:vulns:full
```

The full OSV archive is useful when you need an offline local vulnerability
database, need repeatable point-in-time broad scans, or want to process large
dependency inventories without making one API request per package/version.

## Current Gaps

- OpenSSF Criticality Score is kept separate from health, but this v0 collector
  does not pull a canonical project-level Criticality Score endpoint. It writes
  a local criticality proxy from repository, registry, and enterprise exposure
  evidence.
- Enterprise exposure still comes from the input record. Real enterprise counts
  should come from SBOM, dependency inventory, CMDB, service catalog, or runtime
  ownership data. The browser now derives exposure from selected Risk Navigator
  collections when available; tier-1, internet-facing, and regulated counts
  remain zero unless those fields are added to Risk Navigator datasets.
- Package-level OSV queries identify known vulnerabilities affecting some
  versions of a package. To prove deployed-version impact, run exact
  package-version OSV queries from SBOM data.
- System libraries need distro-specific OSV coordinates. For example, OpenSSL
  can be queried as `Debian/openssl`, `Ubuntu/openssl`, `AlmaLinux/openssl`, or
  `Rocky Linux/openssl`; generic `system/openssl` or `rpm/openssl` is treated
  as not applicable in the browser.
- Organizational diversity, elephant factor, bus factor, contributor churn, and
  anomaly-risk signals are documented as v1 inputs but are not fully collected
  by the current lightweight collector.
