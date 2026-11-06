import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { summarizePipelineStatusForCollection } from '../tool/pipeline-status.mjs';

const statusDoc = JSON.parse(
  readFileSync(new URL('../data/pipeline-status.json', import.meta.url), 'utf8')
);

test('summarizes pipeline status for Risk Navigator and OSS Project Risk without silently switching pinned dataset (#73)', () => {
  const finos = summarizePipelineStatusForCollection(statusDoc, 'finos-github-org', 'finos-github-org-20261103', '2026-11-06T00:00:00Z');
  assert.equal(finos.available, true);
  assert.equal(finos.silently_switch_dataset, false);
  assert.equal(finos.currently_published_snapshot_id, 'finos-github-org-20261103');

  const ossRisk = summarizePipelineStatusForCollection(statusDoc, 'oss-project-risk', 'oss-risk-20261104', '2026-11-06T00:00:00Z');
  assert.equal(ossRisk.available, true);
  assert.ok(ossRisk.seed_inventory_limitation.includes('GITHUB_TOKEN'));

  const unavail = summarizePipelineStatusForCollection(null, 'finos-github-org', 'pinned-1');
  assert.equal(unavail.available, false);
  assert.equal(unavail.loaded_snapshot_id, 'pinned-1');
  assert.equal(unavail.silently_switch_dataset, false);
});
