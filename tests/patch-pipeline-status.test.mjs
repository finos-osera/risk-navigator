import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import {
  resolveCollectionIdFromDataset,
  summarizePipelineStatusForCollection,
} from '../tool/pipeline-status.mjs';

const statusDoc = JSON.parse(
  readFileSync(new URL('../data/pipeline-status.json', import.meta.url), 'utf8')
);

test('summarizes pipeline status for Risk Navigator and OSS Project Risk without silently switching pinned dataset (#73)', () => {
  const finos = summarizePipelineStatusForCollection(statusDoc, 'finos-github-org', 'finos-github-org-20261103', '2026-11-06T00:00:00Z');
  assert.equal(finos.available, true);
  assert.equal(finos.silently_switch_dataset, false);
  assert.equal(finos.currently_published_snapshot_id, 'finos-github-org-20261103');
  assert.equal(finos.currently_published_content_sha256, '08dd6ec40eaa07e0c4f1c8b01861ecde1dcb67879d8dce3643b520ee2e17ad41');
  assert.ok(existsSync(new URL(finos.receipt_url, new URL('../tool/risk-navigator.html', import.meta.url))));
  assert.ok(existsSync(new URL(finos.coverage_url, new URL('../tool/risk-navigator.html', import.meta.url))));

  const ossRisk = summarizePipelineStatusForCollection(statusDoc, 'oss-project-risk', 'oss-risk-20261104', '2026-11-06T00:00:00Z');
  assert.equal(ossRisk.available, true);
  assert.ok(ossRisk.seed_inventory_limitation.includes('GITHUB_TOKEN'));
  assert.ok(existsSync(new URL(ossRisk.receipt_url, new URL('../tool/risk-navigator.html', import.meta.url))));

  // Omitted nowIso uses actual current clock rather than a hardcoded date
  const dynamicClock = summarizePipelineStatusForCollection(statusDoc, 'finos-github-org', 'finos-github-org-20261103');
  assert.equal(dynamicClock.available, true);
  assert.notEqual(dynamicClock.evaluated_at, '2026-11-06T00:00:00Z');

  // Resolves collection IDs from dataset URLs and metadata
  assert.equal(resolveCollectionIdFromDataset('../data/finos-github-org.json'), 'finos-github-org');
  assert.equal(resolveCollectionIdFromDataset('../data/finos-labs.json'), 'finos-labs');
  assert.equal(resolveCollectionIdFromDataset('./data/finos-osera-backpatch-scorecards.json'), 'oss-project-risk');
  assert.equal(resolveCollectionIdFromDataset('../data/finos-sample-platform.json'), null);

  const unavail = summarizePipelineStatusForCollection(null, 'finos-github-org', 'pinned-1');
  assert.equal(unavail.available, false);
  assert.equal(unavail.loaded_snapshot_id, 'pinned-1');
  assert.equal(unavail.silently_switch_dataset, false);
});
