import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  evaluateOseraPriority,
  rankPatchOpportunities,
  assemblePortfolioPlan,
  detectPlanSnapshotDrift,
  exportOwnerChangePackage,
} from '../tool/patches/planner.mjs';

const fixture = JSON.parse(
  readFileSync(new URL('../data/fixtures/patch-opportunity-planner/representative-estate-opportunities.json', import.meta.url), 'utf8')
);

test('reproduces OSERA P0/P1/P2 inclusion rules, medium-with-signal, and unknown signal preservation (#26)', () => {
  const ranked = rankPatchOpportunities(fixture, {});
  const byId = Object.fromEntries(ranked.opportunities.map(o => [o.opportunity_id, o]));

  assert.equal(byId['opp-osera-spring-web-kev'].source_priority, 'P0');
  assert.equal(byId['opp-osera-spring-web-kev'].source_priority_rule, 'OSERA-P0-KEV');
  assert.equal(byId['opp-upstream-tomcat-core'].source_priority, 'P1');
  assert.equal(byId['opp-commercial-tomcat-bom-medium-signal'].source_priority, 'P1');
  assert.equal(byId['opp-commercial-tomcat-bom-medium-signal'].source_priority_rule, 'OSERA-P1-MEDIUM-WITH-SIGNAL');
  assert.equal(byId['opp-baseline-p2-unknown-signal'].source_priority, 'P2');
  assert.deepEqual(byId['opp-baseline-p2-unknown-signal'].unknown_signal_advisories, ['GHSA-unknown-cvss-epss']);
});

test('company policy explains rank changes without overwriting source priority and blocks unready rows (#26, #27)', () => {
  const ranked = rankPatchOpportunities(fixture);
  const byId = Object.fromEntries(ranked.opportunities.map(o => [o.opportunity_id, o]));

  const bom = byId['opp-commercial-tomcat-bom-medium-signal'];
  assert.equal(bom.source_priority, 'P1');
  assert.equal(bom.company_priority, 'P0');
  assert.equal(bom.osera_baseline_rank, 2);
  assert.equal(bom.ready_rank, 1);
  assert.equal(bom.rank_changed_by_company_policy, true);

  assert.equal(byId['opp-blocked-netty-evidence'].queue, 'blocked');
  assert.equal(byId['opp-blocked-netty-evidence'].ready_rank, null);
  assert.equal(byId['opp-ambiguous-guava-identity'].queue, 'investigate');
  assert.equal(byId['opp-unmet-coverage-commons-io'].queue, 'request_coverage');
});

test('deduplicates overlapping library and framework BOM portfolio credit and suppresses unsafe recipes (#26, #27)', () => {
  const ranked = rankPatchOpportunities(fixture);
  const portfolio = assemblePortfolioPlan(ranked, { owner: 'team-payments' });
  assert.equal(portfolio.selected_count, 3);
  assert.equal(portfolio.portfolio_metrics.duplicate_overlap_prevented, 2);
  assert.deepEqual(portfolio.portfolio_metrics.residual_unique_advisories, ['CVE-2024-23672']);

  const byId = Object.fromEntries(ranked.opportunities.map(o => [o.opportunity_id, o]));
  assert.ok(byId['opp-osera-spring-web-kev'].recipe_guidance.openrewrite_recipe);
  assert.equal(byId['opp-upstream-tomcat-core'].recipe_guidance.openrewrite_recipe, null);

  const exported = exportOwnerChangePackage(ranked, portfolio);
  assert.equal(exported.schema_version, 'osera-owner-change-package/v1');
  assert.equal(exported.change_packages.length, 3);
  assert.ok(exported.exports.markdown.includes('# OSERA Owner-Ready Patch Change Package'));
  assert.ok(exported.exports.csv.includes('opp-commercial-tomcat-bom-medium-signal'));
  assert.equal(exported.exports.cyclonedx_vex.bomFormat, 'CycloneDX');
});

test('handles pipe-delimited application IDs, independent occurrences, target-version residuals, and snapshot drift (#26, #27)', () => {
  const payload = {
    opportunities: [
      {
        opportunity_id: 'opp-spring-mod-a',
        action_kind: 'library_patch',
        library: 'org.springframework:spring-web',
        deployed_purl: 'pkg:maven/org.springframework/spring-web@5.3.18',
        framework_or_runtime: 'spring-5.3',
        owner: 'team-payments',
        change_window: 'standard_weekly',
        identity_status: 'confirmed',
        dependency_scope: 'direct',
        affected_applications: ['github|acme|payments|main'],
        advisories: [{ id: 'CVE-2024-22243', kev: true, cvss_score: 8.1, epss_probability: 0.42 }],
        options: [
          {
            patch_id: 'spring-5.3.18-osera-1',
            provider: 'OSERA',
            provider_kind: 'osera',
            replacement_purl: 'pkg:maven/org.springframework/spring-web@5.3.18-osera-00001',
            ready: true,
            fixed_advisories: ['CVE-2024-22243'],
            residual_advisories: ['CVE-2024-99999'],
          },
        ],
      },
      {
        opportunity_id: 'opp-spring-mod-b',
        action_kind: 'library_patch',
        library: 'org.springframework:spring-web',
        deployed_purl: 'pkg:maven/org.springframework/spring-web@5.3.20',
        framework_or_runtime: 'spring-5.3',
        owner: 'team-payments',
        change_window: 'standard_weekly',
        identity_status: 'confirmed',
        dependency_scope: 'direct',
        affected_applications: ['github|acme|payments|main'],
        advisories: [{ id: 'CVE-2024-22243', kev: true, cvss_score: 8.1, epss_probability: 0.42 }],
        options: [
          {
            patch_id: 'spring-5.3.20-osera-1',
            provider: 'OSERA',
            provider_kind: 'osera',
            replacement_purl: 'pkg:maven/org.springframework/spring-web@5.3.20-osera-00001',
            ready: true,
            fixed_advisories: ['CVE-2024-22243'],
            residual_advisories: [],
          },
        ],
      },
    ],
  };

  const ranked = rankPatchOpportunities(payload);
  assert.equal(ranked.summary_metrics.affected_application_count, 1);
  assert.equal(ranked.summary_metrics.exposure_instance_count, 2);

  const plan = assemblePortfolioPlan(ranked);
  assert.equal(plan.portfolio_metrics.deduplicated_addressed_exposure_instances, 2);
  assert.equal(plan.portfolio_metrics.duplicate_overlap_prevented, 0);
  assert.equal(plan.portfolio_metrics.affected_application_count, 1);
  assert.deepEqual(plan.portfolio_metrics.residual_unique_advisories, ['CVE-2024-99999']);
  assert.equal(plan.portfolio_metrics.residual_exposure_instance_count, 1);

  const pkg = exportOwnerChangePackage(ranked, plan);
  assert.equal(detectPlanSnapshotDrift(pkg, ranked).drifted, false);

  const mutated = structuredClone(payload);
  mutated.opportunities[0].options[0].ready = false;
  mutated.opportunities[0].options[0].blocked_reasons = ['withdrawn_artifact'];
  const driftedReport = detectPlanSnapshotDrift(pkg, rankPatchOpportunities(mutated));
  assert.equal(driftedReport.drifted, true);
  assert.equal(driftedReport.catalog_options_changed, true);
});

test('keeps assessment scope independent of selected actions and preserves distinct components in the same deployment (#26, #27)', () => {
  const payload = {
    opportunities: [
      {
        opportunity_id: 'opp-comp-a-prod-eu',
        action_kind: 'library_patch',
        library: 'org.example:comp-a',
        deployed_purl: 'pkg:maven/org.example/comp-a@1.0.0',
        deployment_id: 'prod-eu',
        framework_or_runtime: 'spring-6',
        owner: 'team-payments',
        change_window: 'standard_weekly',
        identity_status: 'confirmed',
        dependency_scope: 'direct',
        affected_applications: ['payments-app'],
        advisories: [{ id: 'CVE-2026-1111', kev: false, cvss_score: 8.2 }],
        options: [
          {
            patch_id: 'comp-a-1.0.1',
            provider: 'Upstream',
            provider_kind: 'upstream',
            replacement_purl: 'pkg:maven/org.example/comp-a@1.0.1',
            ready: true,
            fixed_advisories: ['CVE-2026-1111'],
            residual_advisories: [],
          },
        ],
      },
      {
        opportunity_id: 'opp-comp-b-prod-eu',
        action_kind: 'library_patch',
        library: 'org.example:comp-b',
        deployed_purl: 'pkg:maven/org.example/comp-b@2.0.0',
        deployment_id: 'prod-eu',
        framework_or_runtime: 'spring-6',
        owner: 'team-payments',
        change_window: 'standard_weekly',
        identity_status: 'confirmed',
        dependency_scope: 'direct',
        affected_applications: ['payments-app'],
        advisories: [{ id: 'CVE-2026-1111', kev: false, cvss_score: 8.2 }],
        options: [
          {
            patch_id: 'comp-b-2.0.1',
            provider: 'Upstream',
            provider_kind: 'upstream',
            replacement_purl: 'pkg:maven/org.example/comp-b@2.0.1',
            ready: true,
            fixed_advisories: ['CVE-2026-1111'],
            residual_advisories: [],
          },
        ],
      },
      {
        opportunity_id: 'opp-unpatchable-comp-c-prod-eu',
        action_kind: 'library_patch',
        library: 'org.example:comp-c',
        deployed_purl: 'pkg:maven/org.example/comp-c@3.0.0',
        deployment_id: 'prod-eu',
        framework_or_runtime: 'spring-6',
        owner: 'team-payments',
        change_window: 'standard_weekly',
        identity_status: 'confirmed',
        dependency_scope: 'direct',
        affected_applications: ['payments-app'],
        advisories: [{ id: 'CVE-2026-2222', kev: false, cvss_score: 7.5 }],
        options: [],
      },
    ],
  };

  const ranked = rankPatchOpportunities(payload);
  assert.equal(ranked.summary_metrics.exposure_instance_count, 3);

  const partialPlan = assemblePortfolioPlan(ranked, { selected_opportunity_ids: ['opp-comp-a-prod-eu'] });
  assert.equal(partialPlan.selected_count, 1);
  assert.equal(partialPlan.portfolio_metrics.total_scope_exposure_instances, 3);
  assert.equal(partialPlan.portfolio_metrics.deduplicated_addressed_exposure_instances, 1);
  assert.equal(partialPlan.portfolio_metrics.residual_exposure_instance_count, 2);
  assert.deepEqual(partialPlan.portfolio_metrics.residual_unique_advisories.sort(), ['CVE-2026-1111', 'CVE-2026-2222']);

  const fullPlan = assemblePortfolioPlan(ranked);
  assert.equal(fullPlan.selected_count, 2);
  assert.equal(fullPlan.portfolio_metrics.total_scope_exposure_instances, 3);
  assert.equal(fullPlan.portfolio_metrics.deduplicated_addressed_exposure_instances, 2);
  assert.equal(fullPlan.portfolio_metrics.residual_exposure_instance_count, 1);
  assert.deepEqual(fullPlan.portfolio_metrics.residual_unique_advisories, ['CVE-2026-2222']);
});
