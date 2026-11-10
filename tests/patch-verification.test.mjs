import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  reconcilePatchPlansWithObservations,
  validateAndNormalizeCoverageRequest,
  buildPrivacyPreservingRequestExport,
  deduplicateAuthenticatedIntakeSubmissions,
} from '../tool/patches/verification.mjs';

const reconFixture = JSON.parse(
  readFileSync(new URL('../data/fixtures/patch-verification-requests/patch-plan-reconciliation-fixture.json', import.meta.url), 'utf8')
);
const reqFixture = JSON.parse(
  readFileSync(new URL('../data/fixtures/patch-verification-requests/coverage-request-and-intake-fixture.json', import.meta.url), 'utf8')
);

test('reconciles patch plans and never credits closed tickets or scope drift as verified remediation (#28)', () => {
  const report = reconcilePatchPlansWithObservations(reconFixture);
  const byId = Object.fromEntries(report.plans.map(p => [p.plan_id, p]));

  assert.equal(byId['plan-verified-full-rollout'].reconciled_stage, 'verified');
  assert.equal(byId['plan-closed-ticket-no-deployment'].reconciled_stage, 'planned');
  assert.equal(byId['plan-closed-ticket-no-deployment'].observed_remediated_exposures.length, 0);
  assert.equal(byId['plan-partial-rollout-and-stale-inventory'].reconciled_stage, 'partial_rollout_with_stale_inventory');
  assert.equal(byId['plan-failed-validation'].reconciled_stage, 'validation_failed');
  assert.equal(byId['plan-rollback-reopened'].reconciled_stage, 'reopened_rollback');
  assert.equal(byId['plan-withdrawn-artifact-reopened'].reconciled_stage, 'reopened_withdrawn_artifact');
  assert.equal(byId['plan-scope-drift-only'].reconciled_stage, 'inventory_scope_drift_only');
  assert.equal(report.summary.inventory_or_scope_drift_exposure_count, 1);
});

test('exports privacy-preserving requests, preserves broad-major precision, and enforces k-anonymity intake deduplication (#29, #42)', () => {
  assert.throws(() => validateAndNormalizeCoverageRequest({ package: 'openssl', line: '3.0.1', precision: 'exact', advisories: ['CVE-2024-0727'] }), /coerce to Maven/);

  const bundle = buildPrivacyPreservingRequestExport(reqFixture.raw_requests, {
    existing_catalog_patches: reqFixture.existing_catalog_patches,
    existing_osera_work: reqFixture.existing_osera_work,
    co_released_group_mapping: reqFixture.co_released_group_mapping,
  });
  assert.equal(bundle.requests.length, 2);
  assert.ok(!JSON.stringify(bundle).includes('PRIVATE-BANK-APP-01'));
  const tomcat = bundle.requests.find(r => r.package.includes('tomcat-embed-core'));
  assert.equal(tomcat.scope.confirmed_exact_inventory, false);

  const intake = deduplicateAuthenticatedIntakeSubmissions(reqFixture.intake_submissions, 2);
  const spring = intake.public_lines.find(l => l.package.includes('spring-web'));
  const commons = intake.public_lines.find(l => l.package.includes('commons-io'));
  assert.equal(spring.unique_member_demand_count, 2);
  assert.equal(spring.duplicate_submissions_collapsed, 1);
  assert.equal(commons.rare_request_privacy_redacted, true);
});

test('preserves multi-occurrence deployment observations deterministically across regions, environments, and timestamps (#28)', () => {
  const obsList = [
    {
      application_id: 'payments-gateway',
      deployment_id: 'prod-eu',
      environment: 'production',
      observed_purl: 'pkg:maven/org.springframework/spring-web@5.3.20-osera-00002',
      observed_at: '2026-10-28T10:00:00Z',
      validation_status: 'passed',
    },
    {
      application_id: 'payments-gateway',
      deployment_id: 'prod-us',
      environment: 'production',
      observed_purl: 'pkg:maven/org.springframework/spring-web@5.3.20',
      observed_at: '2026-10-28T10:05:00Z',
      validation_status: 'pending',
    },
    {
      application_id: 'payments-gateway',
      deployment_id: 'staging-1',
      environment: 'staging',
      observed_purl: 'pkg:maven/org.springframework/spring-web@5.3.20',
      observed_at: '2026-10-29T00:00:00Z',
      validation_status: 'failed',
    },
    {
      application_id: 'payments-gateway',
      deployment_id: 'prod-eu',
      environment: 'production',
      observed_purl: 'pkg:maven/org.springframework/spring-web@5.3.20',
      observed_at: '2026-10-25T08:00:00Z',
      validation_status: 'pending',
    },
  ];
  const plans = [
    {
      plan_id: 'plan-whole-prod',
      opportunity_id: 'opp-spring-web',
      current_stage: 'deployed',
      source_artifact_purl: 'pkg:maven/org.springframework/spring-web@5.3.20',
      selected_artifact_purl: 'pkg:maven/org.springframework/spring-web@5.3.20-osera-00002',
      required_environment: 'production',
      target_applications: ['payments-gateway'],
      expected_fixed_advisories: ['CVE-2024-22243'],
    },
    {
      plan_id: 'plan-eu-only',
      opportunity_id: 'opp-spring-web-eu',
      current_stage: 'deployed',
      source_artifact_purl: 'pkg:maven/org.springframework/spring-web@5.3.20',
      selected_artifact_purl: 'pkg:maven/org.springframework/spring-web@5.3.20-osera-00002',
      required_environment: 'production',
      target_applications: ['payments-gateway'],
      target_deployments: ['prod-eu'],
      expected_fixed_advisories: ['CVE-2024-22243'],
    },
  ];

  const repForward = reconcilePatchPlansWithObservations({ deployment_observations: obsList, plans });
  const repReverse = reconcilePatchPlansWithObservations({ deployment_observations: [...obsList].reverse(), plans });
  assert.deepEqual(repForward, repReverse);

  const byId = Object.fromEntries(repForward.plans.map(p => [p.plan_id, p]));
  assert.equal(byId['plan-whole-prod'].reconciled_stage, 'partial_rollout');
  assert.deepEqual(byId['plan-whole-prod'].residual_exposures, ['payments-gateway|CVE-2024-22243']);
  assert.deepEqual(byId['plan-whole-prod'].occurrence_breakdown.verified_occurrences, ['payments-gateway@prod-eu']);
  assert.deepEqual(byId['plan-whole-prod'].occurrence_breakdown.unpatched_occurrences, ['payments-gateway@prod-us']);

  assert.equal(byId['plan-eu-only'].reconciled_stage, 'verified');
  assert.deepEqual(byId['plan-eu-only'].observed_remediated_exposures, ['payments-gateway@prod-eu|CVE-2024-22243']);
  assert.deepEqual(byId['plan-eu-only'].occurrence_breakdown.out_of_scope_unpatched_occurrences, ['payments-gateway@prod-us']);
});

test('keeps distinct clusters in the same region separate and compares ISO timestamps by UTC instant (#28)', () => {
  const obsList = [
    {
      application_id: 'payments-gateway',
      region: 'eu',
      cluster: 'blue',
      environment: 'production',
      observed_purl: 'pkg:maven/org.springframework/spring-web@5.3.20',
      observed_at: '2026-10-28T12:00:00+02:00',
      validation_status: 'pending',
    },
    {
      application_id: 'payments-gateway',
      region: 'eu',
      cluster: 'blue',
      environment: 'production',
      observed_purl: 'pkg:maven/org.springframework/spring-web@5.3.20-osera-00002',
      observed_at: '2026-10-28T10:30:00Z',
      validation_status: 'passed',
    },
    {
      application_id: 'payments-gateway',
      region: 'eu',
      cluster: 'green',
      environment: 'production',
      observed_purl: 'pkg:maven/org.springframework/spring-web@5.3.20',
      observed_at: '2026-10-28T10:35:00Z',
      validation_status: 'pending',
    },
  ];
  const plans = [
    {
      plan_id: 'plan-eu-region',
      opportunity_id: 'opp-spring-web-eu',
      current_stage: 'deployed',
      source_artifact_purl: 'pkg:maven/org.springframework/spring-web@5.3.20',
      selected_artifact_purl: 'pkg:maven/org.springframework/spring-web@5.3.20-osera-00002',
      required_environment: 'production',
      target_applications: ['payments-gateway'],
      target_regions: ['eu'],
      expected_fixed_advisories: ['CVE-2024-22243'],
    },
  ];

  const repFwd = reconcilePatchPlansWithObservations({ deployment_observations: obsList, plans });
  const repRev = reconcilePatchPlansWithObservations({ deployment_observations: [...obsList].reverse(), plans });
  assert.deepEqual(repFwd, repRev);

  const planRes = repFwd.plans[0];
  assert.equal(planRes.reconciled_stage, 'partial_rollout');
  assert.deepEqual(planRes.occurrence_breakdown.verified_occurrences, ['payments-gateway@eu/blue']);
  assert.deepEqual(planRes.occurrence_breakdown.unpatched_occurrences, ['payments-gateway@eu/green']);
  assert.deepEqual(planRes.observed_remediated_exposures, ['payments-gateway@eu/blue|CVE-2024-22243']);
  assert.deepEqual(planRes.residual_exposures, ['payments-gateway@eu/green|CVE-2024-22243']);
});
