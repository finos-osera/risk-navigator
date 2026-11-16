// Shared pipeline-status contract consumer for Risk Navigator and OSS Project Risk (Refs #73 Phase 1 Foundation).

const URL_USERINFO_RE = /(https?:\/\/)[^/\s:@]+:[^/\s@]+@/gi;
const QUERY_PARAM_SECRET_RE = /([?&;]\s*(?:api[_-]?key|access[_-]?token|auth[_-]?token|refresh[_-]?token|token|secret|password|passwd|key|auth|sig|signature|credential|bearer|client[_-]?secret)=)[^&\s#)'"]+/gi;
const AUTH_HEADER_QUOTED_RE = /((?:["'])?(?:proxy-)?authorization(?:["'])?\s*[:=]\s*)(["'])(?:\\.|(?!\2).)*\2/gi;
const AUTH_HEADER_RE = /\b((?:proxy-)?authorization\s*[:=]\s*)(?!\[REDACTED_CREDENTIAL\])(?:(?:Digest|AWS4-HMAC-SHA256)\s+[^\r\n"')\]}]+|[A-Za-z][A-Za-z0-9._-]*\s+(?!(?:while|when|during|after|before|for|from|in|on|at|with|failed|returned)\b)[^\s,;"')\]}]+|[^\s,;"')\]}]+)/gi;
const SECRET_TOKEN_RE = /(?:gh[pousr]_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+|glpat-[A-Za-z0-9_-]+|xox[baprs]-[A-Za-z0-9-]+|AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9_-]{12,}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9._-]+|\b(?:Bearer|Basic|Token|DPoP|ApiKey)\s+[^\s,;"')\]}]+|token=[A-Za-z0-9._~+/=-]+)/gi;
const KEY_VALUE_SECRET_RE = /(\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|refresh[_-]?token|secret|password|passwd|client[_-]?secret)\s*[:=]\s*['"]?)(?!\[REDACTED_CREDENTIAL\])[^\s,'";)\]}]+/gi;
const FILESYSTEM_PATH_RE = /(?:\/(?:Users|home|var|tmp|private|opt|etc|srv|root|runner|work|workspace|workspaces|github|app|proc)[^\s'":;)]*|[A-Za-z]:\\[^\s'":;)]+)/g;

export function sanitizePublicFailureSummary(rawMessage) {
  if (!rawMessage) return null;
  let msg = String(rawMessage).trim();
  msg = msg.replace(URL_USERINFO_RE, '$1[REDACTED_CREDENTIAL]@');
  msg = msg.replace(QUERY_PARAM_SECRET_RE, '$1[REDACTED_CREDENTIAL]');
  msg = msg.replace(AUTH_HEADER_QUOTED_RE, '$1$2[REDACTED_CREDENTIAL]$2');
  msg = msg.replace(AUTH_HEADER_RE, '$1[REDACTED_CREDENTIAL]');
  msg = msg.replace(SECRET_TOKEN_RE, '[REDACTED_CREDENTIAL]');
  msg = msg.replace(KEY_VALUE_SECRET_RE, '$1[REDACTED_CREDENTIAL]');
  msg = msg.replace(FILESYSTEM_PATH_RE, '[REDACTED_PATH]');
  return msg.slice(0, 240);
}

export function resolveCollectionIdFromDataset(datasetUrl, datasetMeta = null) {
  const scopeName = String(datasetMeta?.scope_name || '').trim();
  if (scopeName === 'finos-github-org' || scopeName === 'finos-labs' || scopeName === 'oss-project-risk') {
    return scopeName;
  }
  const url = String(datasetUrl || '').trim();
  if (url.includes('finos-github-org.json')) return 'finos-github-org';
  if (url.includes('finos-labs.json')) return 'finos-labs';
  if (url.includes('finos-osera-backpatch-scorecards.json') || url.includes('oss-risk')) return 'oss-project-risk';
  return null;
}

export function summarizePipelineStatusForCollection(
  statusDoc,
  collectionId,
  loadedSnapshotId = null,
  nowIso = null,
  maxStaleSeconds = 172800
) {
  const effectiveNowIso = nowIso || new Date().toISOString();
  if (!statusDoc || typeof statusDoc !== 'object' || !Array.isArray(statusDoc.pipelines)) {
    return {
      available: false,
      collection_id: collectionId,
      state: 'status_unavailable',
      evaluated_at: effectiveNowIso,
      banner: 'Pipeline status unavailable; continuing with last valid loaded dataset.',
      loaded_snapshot_id: loadedSnapshotId,
      silently_switch_dataset: false,
    };
  }

  const checkedAt = Date.parse(statusDoc.checked_at || statusDoc.generated_at || '');
  const nowMs = Date.parse(effectiveNowIso);
  const feedStale = !Number.isNaN(checkedAt) && !Number.isNaN(nowMs) && ((nowMs - checkedAt) / 1000) > maxStaleSeconds;

  const pipe = statusDoc.pipelines.find(p => p.collection_id === collectionId);
  if (!pipe) {
    return {
      available: false,
      collection_id: collectionId,
      state: 'collection_not_found',
      evaluated_at: effectiveNowIso,
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

  const safeFailureSummary = pipe.failure_summary ? sanitizePublicFailureSummary(pipe.failure_summary) : null;
  let banner = '';
  if (attempt.outcome === 'failed' || attempt.outcome === 'cancelled') {
    banner = `${name}: latest refresh ${attempt.outcome} (${safeFailureSummary || 'check logs'}); ${pipe.previous_valid_snapshot_retained ? 'previous validated snapshot retained' : 'no published snapshot'}.`;
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
    evaluated_at: effectiveNowIso,
    collection_id: collectionId,
    publication_state: pubState,
    latest_attempt_outcome: attempt.outcome || 'unknown',
    latest_validated_candidate_id: candidate?.snapshot_id || null,
    currently_published_snapshot_id: published?.snapshot_id || null,
    currently_published_content_sha256: published?.content_sha256 || null,
    receipt_url: published?.receipt_url || candidate?.receipt_url || null,
    coverage_url: published?.coverage_url || candidate?.coverage_url || null,
    failure_code: pipe.failure_code || null,
    loaded_snapshot_id: loadedSnapshotId,
    newer_published_available: Boolean(published?.snapshot_id && loadedSnapshotId && published.snapshot_id !== loadedSnapshotId),
    silently_switch_dataset: false,
    seed_inventory_limitation: pipe.seed_inventory_limitation || null,
    measurements: pipe.measurements || {},
    banner,
  };
}

let cachedStatusDoc = null;

async function fetchStatusDoc(url = '../data/pipeline-status.json') {
  if (cachedStatusDoc) return cachedStatusDoc;
  try {
    const res = await fetch(url, { credentials: 'omit' });
    if (!res.ok) return null;
    cachedStatusDoc = await res.json();
    return cachedStatusDoc;
  } catch {
    return null;
  }
}

function renderBrowserStatusPill(summary) {
  if (typeof document === 'undefined' || !summary) return;
  const scopeMeta = document.getElementById('scopeMeta');
  if (scopeMeta) {
    const pillsHost = scopeMeta.querySelector('.meta-pills') || scopeMeta;
    let pill = document.getElementById('pipelineStatusPill');
    if (!pill) {
      pill = document.createElement('span');
      pill.id = 'pipelineStatusPill';
      pill.className = 'meta-pill';
      pillsHost.appendChild(pill);
    }
    pill.title = summary.banner || '';
    pill.textContent = summary.currently_published_snapshot_id
      ? `Snapshot: ${summary.currently_published_snapshot_id}`
      : `Pipeline: ${summary.publication_state || summary.state}`;
  }
}

if (typeof window !== 'undefined' && typeof document !== 'undefined') {
  window.riskPipelineStatus = {
    summarizePipelineStatusForCollection,
    resolveCollectionIdFromDataset,
  };
  window.addEventListener('risk-nav:dataset', async event => {
    const ds = event?.detail;
    const collectionId = resolveCollectionIdFromDataset('', ds?.meta);
    if (!collectionId) return;
    const statusDoc = await fetchStatusDoc('../data/pipeline-status.json');
    const summary = summarizePipelineStatusForCollection(statusDoc, collectionId);
    renderBrowserStatusPill(summary);
  });
}
