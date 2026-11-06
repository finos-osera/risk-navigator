// Shared pipeline-status contract consumer for Risk Navigator and OSS Project Risk (#73 Workstream 6 & 7).

export function summarizePipelineStatusForCollection(statusDoc, collectionId, loadedSnapshotId = null, nowIso = '2026-11-06T00:00:00Z', maxStaleSeconds = 172800) {
  if (!statusDoc || typeof statusDoc !== 'object' || !Array.isArray(statusDoc.pipelines)) {
    return {
      available: false,
      collection_id: collectionId,
      state: 'status_unavailable',
      banner: 'Pipeline status unavailable; continuing with last valid loaded dataset.',
      loaded_snapshot_id: loadedSnapshotId,
      silently_switch_dataset: false,
    };
  }

  const checkedAt = Date.parse(statusDoc.checked_at || statusDoc.generated_at || '');
  const nowMs = Date.parse(nowIso);
  const feedStale = !Number.isNaN(checkedAt) && !Number.isNaN(nowMs) && ((nowMs - checkedAt) / 1000) > maxStaleSeconds;

  const pipe = statusDoc.pipelines.find(p => p.collection_id === collectionId);
  if (!pipe) {
    return {
      available: false,
      collection_id: collectionId,
      state: 'collection_not_found',
      banner: `No pipeline status entry for ${collectionId}; continuing with loaded dataset.`,
      loaded_snapshot_id: loadedSnapshotId,
      silently_switch_dataset: false,
    };
  }

  const attempt = pipe.latest_attempt || {};
  const candidate = pipe.latest_validated_candidate || null;
  const published = pipe.currently_published_snapshot || null;
  const pubState = pipe.publication_state || 'unknown';
  const name = pipe.friendly_name || collectionId;

  let banner = '';
  if (attempt.outcome === 'failed' || attempt.outcome === 'cancelled') {
    banner = `${name}: latest refresh ${attempt.outcome} (${pipe.failure_summary || 'check logs'}); ${pipe.previous_valid_snapshot_retained ? 'previous validated snapshot retained' : 'no published snapshot'}.`;
  } else if (pubState === 'refresh_succeeded_pr_awaiting_review' && candidate) {
    banner = `${name}: refresh succeeded; new snapshot ${candidate.snapshot_id} awaiting review${pipe.pending_pr_url ? ' in PR ' + pipe.pending_pr_url : ''}; currently viewing snapshot ${loadedSnapshotId || published?.snapshot_id || 'loaded'}.`;
  } else if (attempt.outcome === 'unchanged' || pubState === 'published_checked_unchanged') {
    banner = `${name}: current published snapshot ${published?.snapshot_id || 'none'}; evidence checked ${statusDoc.checked_at}; latest refresh found no changes.`;
  } else if (published) {
    banner = `${name}: current published snapshot ${published.snapshot_id} (published ${published.published_at}).`;
  } else {
    banner = `${name}: awaiting initial publication.`;
  }

  return {
    available: true,
    feed_stale: feedStale,
    collection_id: collectionId,
    publication_state: pubState,
    latest_attempt_outcome: attempt.outcome || 'unknown',
    latest_validated_candidate_id: candidate?.snapshot_id || null,
    currently_published_snapshot_id: published?.snapshot_id || null,
    loaded_snapshot_id: loadedSnapshotId,
    newer_published_available: Boolean(published?.snapshot_id && loadedSnapshotId && published.snapshot_id !== loadedSnapshotId),
    silently_switch_dataset: false,
    seed_inventory_limitation: pipe.seed_inventory_limitation || null,
    measurements: pipe.measurements || {},
    banner,
  };
}
