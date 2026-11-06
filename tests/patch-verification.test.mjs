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
