import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import {
  resolveCollectionIdFromDataset,
  sanitizePublicFailureSummary,
  summarizePipelineStatusForCollection,
} from '../tool/pipeline-status.mjs';

const fixtureBaseUrl = new URL('./fixtures/pipeline/tool/risk-navigator.html', import.meta.url);
const statusDoc = JSON.parse(
  readFileSync(new URL('./fixtures/pipeline/data/pipeline-status.json', import.meta.url), 'utf8')
);

test('summarizes fixture pipeline status for Risk Navigator and OSS Project Risk without silently switching pinned dataset (#73)', () => {
  const expectedFinosSnap = statusDoc.pipelines[0].currently_published_snapshot.snapshot_id;
  const expectedFinosSha = statusDoc.pipelines[0].currently_published_snapshot.content_sha256;
  const finos = summarizePipelineStatusForCollection(statusDoc, 'finos-github-org', expectedFinosSnap, '2026-11-06T00:00:00Z');
  assert.equal(finos.available, true);
  assert.equal(finos.silently_switch_dataset, false);
  assert.equal(finos.currently_published_snapshot_id, expectedFinosSnap);
  assert.equal(finos.currently_published_content_sha256, expectedFinosSha);
  assert.ok(existsSync(new URL(finos.receipt_url, fixtureBaseUrl)));
  assert.ok(existsSync(new URL(finos.coverage_url, fixtureBaseUrl)));

  const expectedOssSnap = statusDoc.pipelines[2].currently_published_snapshot.snapshot_id;
  const ossRisk = summarizePipelineStatusForCollection(statusDoc, 'oss-project-risk', expectedOssSnap, '2026-11-06T00:00:00Z');
  assert.equal(ossRisk.available, true);
  assert.ok(ossRisk.seed_inventory_limitation.includes('GITHUB_TOKEN'));
  assert.ok(existsSync(new URL(ossRisk.receipt_url, fixtureBaseUrl)));

  // Omitted nowIso uses actual current clock rather than a hardcoded date
  const dynamicClock = summarizePipelineStatusForCollection(statusDoc, 'finos-github-org', expectedFinosSnap);
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

test('redacts Authorization Bearer/Basic headers, credentials, and runner paths in public failure summaries (#73)', () => {
  assert.equal(
    sanitizePublicFailureSummary('Authorization: Bearer SYNTHETIC_SECRET_123456'),
    'Authorization: [REDACTED_CREDENTIAL]'
  );
  assert.equal(
    sanitizePublicFailureSummary('Authorization: Basic dXNlcjpzZWNyZXRfcGFzc3dvcmQ='),
    'Authorization: [REDACTED_CREDENTIAL]'
  );
  const composite = sanitizePublicFailureSummary(
    "GET https://ci:secret@feed.example/v1?api_key=ak_123 'Authorization': 'Bearer QUOTED_999' /home/runner/work/app/secret.json"
  );
  for (const leaked of ['SYNTHETIC_SECRET_123456', 'dXNlcjpzZWNyZXRfcGFzc3dvcmQ', 'secret', 'ak_123', 'QUOTED_999', '/home/runner/work']) {
    assert.equal(composite.includes(leaked), false, `Expected ${leaked} to be redacted in: ${composite}`);
  }
});

test('packaged HTML entrypoints do not reference uncopied pipeline-status module assets in Phase 1 (#73)', () => {
  const navHtml = readFileSync(new URL('../tool/risk-navigator.html', import.meta.url), 'utf8');
  const ossHtml = readFileSync(new URL('../oss-risk/browser.html', import.meta.url), 'utf8');
  assert.equal(navHtml.includes('pipeline-status.mjs'), false);
  assert.equal(ossHtml.includes('pipeline-status.mjs'), false);
});
