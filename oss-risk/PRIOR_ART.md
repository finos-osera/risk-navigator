# Prior Art to Compose

This model should compose mature OSS risk and health work rather than invent a
bespoke index from scratch.

## CHAOSS

CHAOSS is the main foundation for project vitality and sustainability metrics.
The scorecard should map to these concepts:

- Bus factor and maintainer concentration.
- Release frequency.
- Time to first response.
- Change-request closure ratio.
- Organizational diversity.
- Elephant factor: whether contribution is concentrated in a small number of
  companies.

Implementation status:

- Current collector captures commit/contributor windows, release recency,
  issue closure ratio, and PR merge latency from GitHub.
- Still needed: real maintainer bus factor, contributor churn, new contributor
  rate, contributor affiliation, organizational diversity, and elephant factor.

## OpenSSF Scorecard

OpenSSF Scorecard is the security-practice component. We should ingest its
individual checks rather than recreating them.

Implementation status:

- Current collector pulls the repository score and check details from the
  Scorecard API.
- Security posture scoring uses the relevant check scores as an input.
- The browser shows the raw check evidence in source provenance.

## OpenSSF Criticality Score

Criticality is an importance signal, not a health signal. A project can be
critical and healthy; criticality should make weaknesses matter more, not make
the project look unhealthy.

Implementation status:

- Current collector keeps criticality separate.
- A local proxy is computed from stars, dependents, downloads, and enterprise
  application exposure.
- Still needed: canonical OpenSSF Criticality Score ingestion when a suitable
  project-level dataset or endpoint is wired in.

## OWASP Dependency-Track and SBOM Tooling

Dependency-Track is the architectural reference for portfolio-level SBOM risk
analysis: continuously inventory components, correlate vulnerabilities, and use
signals such as EPSS to prioritize.

Implementation status:

- Current OSS-risk records accept enterprise exposure as an overlay.
- Existing Risk Navigator data pipelines already ingest SBOM/dependency graph
  data for vulnerability prioritization.
- Still needed: direct bridge from Risk Navigator SBOM scope datasets into
  OSS-risk enterprise overlay records.

## Underproduction Research

Underproduction frames risk as a mismatch between maintenance supply and
downstream demand. This is the basis for our maintenance load ratio.

Implementation status:

- Current records include `undermaintenance_pressure`.
- The current formula uses dependents, downloads, and internal application count
  as demand, divided by contributor/maintainer activity as capacity.
- Still needed: better capacity terms for funding, foundation support,
  maintainer time, and organization diversity.

## OSDRI Shape

The mature-art-informed model is:

```text
OSS failure / compromise likelihood
  = vitality weakness
  + maintainer resilience weakness
  + governance weakness
  + security posture weakness
  + vulnerability weakness
  + dependency health weakness
  + change/anomaly warning signals

Enterprise priority
  = OSS failure / compromise likelihood
  x external criticality
  x internal exposure
  x business criticality
```

Keep popularity, criticality, and exposure out of the health score. They are
multipliers and routing signals.

## V1 Metric Set

Start with metrics that can be explained and back-tested:

| Area | V1 fields |
|---|---|
| Vitality | active contributors 90d/365d, activity trend, release recency, issue closure ratio, PR merge latency |
| Maintainer resilience | bus factor, contributor concentration, maintainer churn, new contributor rate |
| Governance | governance model, foundation or independent entity, corporate diversity, security policy |
| Security posture | OpenSSF Scorecard checks, signed releases, branch protection, code review, dependency update tooling |
| Vulnerability health | unresolved vulnerabilities by severity, EPSS, KEV, remediation time |
| Dependency health | stale direct dependencies, vulnerable transitives, dependency depth, unsupported runtimes |
| Criticality | OpenSSF Criticality Score, dependents, downloads, enterprise application count |
| Change/anomaly risk | sudden maintainer turnover, ownership changes, unusual releases, new maintainer publishing patterns |

The weights should be calibrated against 100-500 known libraries classified by
engineering/security reviewers as healthy, watchlisted, abandoned, or
operationally critical.

