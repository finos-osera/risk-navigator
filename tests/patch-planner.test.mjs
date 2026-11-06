import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  evaluateOseraPriority,
  rankPatchOpportunities,
  assemblePortfolioPlan,
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
});
