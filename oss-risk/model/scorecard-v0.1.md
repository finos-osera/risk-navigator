# OSS Library Risk Scorecard v0.1

## Design Principles

The scorecard uses public OSS health models where they are strong, then adds an
enterprise overlay where public data cannot answer the question.

- Compose mature models instead of adopting any one of them wholesale:
  CHAOSS for project health and organizational resilience, OpenSSF Scorecard
  for security posture, OpenSSF Criticality Score for importance, SBOM/SCA
  tooling patterns for portfolio vulnerability exposure, and underproduction
  research for maintenance load.
- Keep public project health separate from enterprise exposure.
- Keep ecosystem criticality separate from project health.
- Keep security history separate from security responsiveness.
- Preserve provenance for every input.
- Prefer reproducible fields over subjective labels.
- Attach confidence to incomplete or model-extracted evidence.

## Outputs

### OSS Failure or Compromise Likelihood

`OSS failure or compromise likelihood` is the internal risk term informed by
vitality, maintainer resilience, governance, security posture, vulnerability
health, dependency health, and anomaly signals. The v0.1 implementation exposes
the healthier-facing `OSS Vitality Score`, but the risk equation should be read
as:

```text
priority_risk =
  P(OSS failure or compromise)
  * external_criticality
  * internal_exposure
  * business_criticality
```

### OSS Vitality Score

`OSS Vitality Score` is a 0-100 score where higher means healthier upstream OSS.

```text
V = .25 * project_vitality
  + .25 * security_health
  + .20 * sustainability_governance
  + .15 * dependency_hygiene
  + .15 * ecosystem_resilience
```

### Enterprise Priority Risk

`Enterprise Priority Risk` is a 0-100 score where higher means the enterprise
should prioritize attention.

```text
health_gap = 100 - oss_vitality_score

enterprise_priority_risk =
  health_gap
  * ecosystem_criticality_factor
  * internal_exposure_factor
  * version_risk_factor
  * confidence_factor
```

All factors are normalized so the final score is clamped to 0-100.

This means a project can be extremely critical without being unhealthy. Critical
projects only become high enterprise priorities when there is also a health,
version, or exposure weakness.

## Dimensions

### 1. Project Vitality, 25%

Project vitality measures whether the project is actively moving and whether
maintenance capacity is trending in the right direction.

| Field | Weight | Source family |
|---|---:|---|
| Active contributors, 365 days | 20% | GitHub/repository |
| Active contributors trend, 365/180/90/30 days | 25% | CHAOSS-derived |
| Release cadence and recency | 20% | Registry/repository |
| Issue closure and PR merge-latency behavior | 15% | CHAOSS-derived |
| Maintainer bus factor | 15% | CHAOSS-derived |
| Project age and continuity | 5% | Registry/repository |

Direction of travel should matter more than raw activity. A mature project with
low but stable maintenance can be healthier than a formerly busy project whose
maintainer base is collapsing.

### 2. Security Health, 25%

Security health measures current security posture and responsiveness.

| Field | Weight | Source family |
|---|---:|---|
| OpenSSF Scorecard security checks | 30% | OpenSSF |
| Known unresolved vulnerabilities | 20% | OSV/GHSA/NVD |
| CISA KEV exposure | 15% | CISA KEV |
| EPSS-weighted exploit likelihood | 10% | FIRST EPSS |
| Vulnerability remediation speed | 15% | OSV/repository |
| Security policy, advisories, signed releases | 10% | OpenSSF/repository |

Historical CVEs should not automatically make a project unhealthy. A project
with frequent security reports and fast fixes may be healthier than one with no
reported issues and weak security process.

### 3. Sustainability and Governance, 20%

Governance measures institutional resilience, not just whether a project has a
well-known corporate or foundation name attached to it.

| Field | Weight | Source family |
|---|---:|---|
| Explicit governance model | 25% | Repository/docs |
| Neutral foundation or independent entity | 20% | Repository/docs |
| Organizational diversity | 20% | Repository/GitHub |
| Maintainer concentration | 15% | CHAOSS-derived |
| Transparent security process | 10% | OpenSSF/repository |
| Funding or commercial sustainability | 10% | Repository/docs |

Corporate backing can improve sustainability, but concentrated control can still
be a risk. Foundation backing should be evidence, not a blanket bonus.

### 4. Dependency Hygiene, 15%

Dependency hygiene measures whether the project keeps its own dependency stack
fresh and supportable.

| Field | Weight | Source family |
|---|---:|---|
| Stale direct dependencies | 25% | deps.dev/registry |
| Vulnerable direct dependencies | 25% | OSV/GHSA/NVD |
| Unsupported runtimes or platforms | 20% | Registry/repository |
| Dependency update cadence | 20% | Repository/automation |
| Transitive risk concentration | 10% | SBOM/dependency graph |

### 5. Ecosystem Resilience, 15%

Ecosystem resilience measures the project's ability to survive disruption and
the wider ecosystem's ability to respond.

| Field | Weight | Source family |
|---|---:|---|
| Dependents or downstream adoption | 25% | Registry/deps.dev |
| Download/use trend | 15% | Registry |
| Contributor ecosystem breadth | 20% | CHAOSS-derived |
| Documentation and release process | 15% | Repository/docs |
| Forkability and build reproducibility | 15% | OpenSSF/repository |
| Project age and installed base stability | 10% | Registry/repository |

## Separate Criticality Signal

Criticality is not part of project health. It is an importance multiplier.

Recommended inputs:

- OpenSSF Criticality Score where available.
- Registry dependents/downloads.
- Number of enterprise applications using the package.
- Whether usage is direct or transitive.
- Whether usage appears in tier-1, regulated, or internet-facing systems.

## Enterprise Overlay

For each deployed package version, attach internal exposure.

| Field | Meaning |
|---|---|
| `versions_in_use` | Package versions observed in SBOM or dependency inventory. |
| `application_count` | Number of applications using the package. |
| `direct_dependency_count` | Applications with the package as a direct dependency. |
| `transitive_dependency_count` | Applications with the package transitively. |
| `tier1_application_count` | Tier-1 or crown-jewel application exposure. |
| `internet_facing_application_count` | Internet-facing application exposure. |
| `regulated_application_count` | Systems with regulatory or customer-data sensitivity. |
| `unsupported_version_count` | Versions that are out of support or abandoned. |
| `known_vulnerable_version_count` | Deployed versions with known CVEs. |

The same public project score can produce very different enterprise priorities
depending on internal adoption.

## Undermaintenance Pressure

Undermaintenance pressure, also called maintenance load ratio, is a watch
signal based on underproduction research. It asks how much ecosystem weight
rests on each unit of maintenance capacity.

```text
UMP = log(1 + downstream_weight)
    / log(2 + active_maintainers + recent_contributors)
```

Good downstream-weight inputs include registry dependents, downloads, and
enterprise application count. The signal is most useful for highlighting
projects with very high adoption and thin maintainer capacity.

## Confidence

Each dimension gets a confidence score from 0-1.

| Confidence | Meaning |
|---:|---|
| 1.0 | Fresh direct source data from official APIs or repository metadata. |
| 0.8 | Fresh data with minor gaps or model-extracted evidence reviewed by rules. |
| 0.6 | Partial data from reliable sources. |
| 0.4 | Sparse evidence or stale snapshots. |
| 0.2 | Mostly inferred; should not drive decisions without review. |

Headline scores should show confidence. A `74` with `0.95` confidence is more
actionable than a `91` with `0.35` confidence.

## Open/Public Models to Reuse

- OpenSSF Scorecard: security posture checks.
- OpenSSF Criticality Score: ecosystem importance.
- CHAOSS starter project health metrics: responsiveness, bus factor, release
  frequency, and contributor health.
- CHAOSS organizational diversity and elephant-factor metrics: corporate
  concentration and affiliation resilience.
- OWASP Dependency-Track/SBOM practice: component inventory, vulnerability
  intelligence correlation, EPSS-informed prioritization, and policy routing.
- Underproduction research: maintenance-supply versus downstream-demand framing.
- OSV/GHSA/NVD: vulnerability records.
- CISA KEV: known exploited vulnerability indicator.
- FIRST EPSS: exploit probability.
- deps.dev and package registries: version, dependency, and usage metadata.

The overlay should not replace these sources. It should join them to the
enterprise's deployed versions and business context.
