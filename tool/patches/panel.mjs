import { normalizeFeed, analyze, activePatches, unique } from './catalog.mjs';
export const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const h = escapeHtml;
const labels = { available: 'Applicable patch available', observed: 'Patched artifact observed', candidate: 'Published fix — check applicability', unconfirmed: 'Evidence unconfirmed / blocked', gap: 'No known patch', unknown: 'Unknown identity' };
const storageKey = 'risk-nav-patch-feeds:v1';
export const patchState = { dataset: null, feeds: [], filters: {}, lastResult: null };
try {
  const saved = JSON.parse(localStorage.getItem(storageKey) || '[]');
  // Re-normalize persisted source documents rather than trust derived match state.
  patchState.feeds = saved.map(s => ({ ...normalizeFeed(s.document, s.source, s.releaseSets), enabled: s.enabled, loaded_at: s.loaded_at || "unknown", document: s.document, releaseSets: s.releaseSets }));
} catch { /* A corrupt browser cache must not stop the original navigator. */ }
const host = document.getElementById('patchCoverage');
host.innerHTML = `<summary>Patch feeds &amp; estate coverage</summary><div class="patch-content">
  <p>Load published patches to find opportunities and observed usage in the selected dataset. These controls are independent of the vulnerability table filters.</p>
  <div class="patch-actions"><button id="loadOsera">Load / refresh OSERA</button><label>Import patch catalog or OpenVEX <input id="patchFile" type="file" accept=".json,application/json"></label></div>
  <div class="patch-actions"><label>Feed URL <input id="patchUrl" type="url" placeholder="https://…/catalog.json"></label><button id="loadPatchUrl">Load URL</button></div>
  <p id="patchMessage" role="status" aria-live="polite"></p><div id="patchSources"></div>
  <div class="patch-actions"><label>Feed <select id="patchFeedFilter"></select></label><label>Application <select id="patchProjectFilter"></select></label>
  <label>State <select id="patchStatusFilter"><option value="">All states</option>${Object.entries(labels).map(([k,v]) => `<option value="${k}">${v}</option>`).join('')}</select></label>
  <label>Package / version / advisory <input id="patchSearch" type="search"></label></div>
  <div id="patchMetrics"></div><p id="patchScope" class="small"></p><div class="patch-scroll"><table><thead><tr><th>Application / component</th><th>Coverage</th><th>Patch evidence</th><th>Remaining findings</th></tr></thead><tbody id="patchRows"></tbody></table></div>
  <div id="patchRequestMount"></div></div>`;
const q = selector => host.querySelector(selector);
function message(text) { q('#patchMessage').textContent = text; }
function save() {
  try { localStorage.setItem(storageKey, JSON.stringify(patchState.feeds.map(({document, source, releaseSets, enabled, loaded_at}) => ({document, source, releaseSets, enabled, loaded_at})))); }
  catch { message('Loaded for this session. Browser storage is full or unavailable.'); }
}
export function installFeed(document, source, releaseSets = null) {
  const feed = { ...normalizeFeed(document, source, releaseSets), document, releaseSets };
  patchState.feeds = patchState.feeds.filter(f => f.id !== feed.id).concat(feed);
  save(); renderCoverage();
  message(`Loaded ${feed.patches.length} records. ${feed.errors.length} invalid records excluded.${feed.errors.length ? ' See source validation details.' : ''}`);
}
async function fetchJson(url) {
  const parsed = new URL(url);
  if (parsed.protocol !== 'https:') throw new Error('Use an HTTPS feed URL.');
  const response = await fetch(parsed, { credentials: 'omit', signal: AbortSignal.timeout(20000) });
  if (!response.ok) throw new Error(`Feed request failed (${response.status}).`);
  return response.json();
}
async function load(button, action) {
  button.disabled = true; message('Loading feed…');
  try { await action(); } catch (error) { message(`${error.message} Previous feed retained. For CORS/network failures, import a downloaded JSON file.`); }
  finally { button.disabled = false; }
}
q('#loadOsera').onclick = event => load(event.target, async () => {
  const [vex, sets] = await Promise.all([fetchJson('https://feed.finos.org/openvex.json'), fetchJson('https://feed.finos.org/sets.json')]);
  installFeed(vex, 'https://feed.finos.org/openvex.json', sets);
});
q('#loadPatchUrl').onclick = event => load(event.target, async () => {
  const url = q('#patchUrl').value.trim(); installFeed(await fetchJson(url), url);
});
q('#patchFile').onchange = async event => {
  const file = event.target.files[0]; if (!file) return;
  try {
    if (file.size > 10 * 1024 * 1024) throw new Error('Feed exceeds the 10 MB import limit.');
    const doc = JSON.parse(await file.text());
    // Offline OSERA bundle preserves the release-set evidence alongside VEX.
    installFeed(doc.openvex || doc, file.name, doc.openvex ? doc.release_sets : null);
  } catch (error) { message(error.message); }
  event.target.value = '';
};
for (const [selector, key] of [['#patchFeedFilter','feed'], ['#patchProjectFilter','project'], ['#patchStatusFilter','status'], ['#patchSearch','search']]) {
  q(selector).addEventListener(key === 'search' ? 'input' : 'change', event => { patchState.filters[key] = event.target.value; renderCoverage(); });
}
const ratio = (a,b) => b ? `${a} / ${b} (${Math.round(100*a/b)}%)` : 'N/A (no eligible observations)';
export function renderCoverage() {
  if (!patchState.dataset) return;
  const { dataset, feeds, filters } = patchState;
  q('#patchFeedFilter').innerHTML = '<option value="">All enabled feeds</option>' + feeds.filter(f => f.enabled).map(f => `<option value="${h(f.id)}">${h(f.provider)}</option>`).join('');
  q('#patchProjectFilter').innerHTML = '<option value="">All applications</option>' + (dataset.consumer_projects || []).map(p => `<option value="${h(p.id)}">${h(p.project_ref || p.id)}</option>`).join('');
  q('#patchFeedFilter').value = filters.feed || ''; q('#patchProjectFilter').value = filters.project || '';
  q('#patchSources').innerHTML = feeds.map((f,index) => `<div class="patch-source"><label><input type="checkbox" data-feed="${index}" ${f.enabled ? 'checked' : ''}> ${h(f.provider)}</label> · version ${h(f.version)} · ${f.patches.length} records · snapshot ${h(f.generated_at)} · loaded ${h(f.loaded_at)} <button data-remove="${index}">Remove</button><div class="small">${h(f.source)}</div>${f.errors.length ? `<details><summary>${f.errors.length} validation errors</summary><pre>${h(f.errors.join('\n'))}</pre></details>` : ''}</div>`).join('') || '<p>No feeds loaded. No known patch does not mean no patch exists.</p>';
  q('#patchSources').querySelectorAll('[data-feed]').forEach(input => input.onchange = () => { feeds[Number(input.dataset.feed)].enabled = input.checked; filters.feed = ''; save(); renderCoverage(); });
  q('#patchSources').querySelectorAll('[data-remove]').forEach(button => button.onclick = () => { feeds.splice(Number(button.dataset.remove),1); filters.feed = ''; save(); renderCoverage(); });
  const result = analyze(dataset, feeds, filters); patchState.lastResult = result;
  q('#patchMetrics').innerHTML = `<div class="patch-metrics"><div><strong>${ratio(result.availableProjects,result.totalProjects)}</strong><br>Applications with applicable patches</div><div><strong>${ratio(result.observedProjects,result.totalProjects)}</strong><br>Applications with observed patch use</div><div><strong>${ratio(result.observed,result.eligible)}</strong><br>Patched / eligible component instances</div><div><strong>${result.candidates}</strong><br>Instances with published candidates</div></div>`;
  const incomplete = dataset.meta?.inventory_complete !== true;
  const truncated = (dataset.libraries || []).some(l => l.consumer_project_ids_truncated || l.cves_truncated);
  q('#patchScope').textContent = `Dataset: ${dataset.meta?.scope_name || 'unnamed'} · snapshot ${dataset.meta?.extracted_at || 'unknown'}. ${incomplete ? 'Partial inventory: this dataset may omit non-vulnerable components; adoption is a lower bound, not estate-wide verification.' : 'Complete inventory declared by source.'} ${truncated ? 'Truncated findings/consumers: counts are lower bounds.' : ''} ${result.unknown} instances have unknown or blocked evidence. Counts use unique project + package/version observations, not deployment proof. Search/feed/application filters scope counts; state filter only narrows rows. Feed and inventory dates may differ; refresh stale snapshots.`;
  q('#patchRows').innerHTML = result.rows.map(row => {
    const matches = [...row.adopted, ...row.available, ...row.candidates, ...row.other];
    const targets = unique(matches.map(p => p.target));
    return `<tr><td>${h(row.project)}<br><code>${h(row.identity || row.library.id)}</code><br><span class="small">${row.direct ? 'Direct' : 'Transitive'} dependency</span></td><td>${h(labels[row.status])}</td><td>${targets.length ? `<details><summary>${targets.length} target artifact(s)</summary>${targets.map(target => `<p><code>${h(target)}</code><br>${h(unique(matches.filter(p => p.target === target).map(p => `${p.provider} · ${p.state} · ${p.status}`)).join('; '))}</p>`).join('')}<p class="small">VEX describes exact products. Candidates require compatibility review; release sets can require companion artifacts.</p><pre>${h(JSON.stringify(matches.map(({document, ...p}) => p),null,2))}</pre></details>` : 'No matching evidence'}</td><td>${h(row.remaining.join(', ') || (row.advisories.length ? 'No remaining listed findings' : 'No listed findings'))}</td></tr>`;
  }).join('') || '<tr><td colspan="4">No component observations match these filters.</td></tr>';
  window.dispatchEvent(new CustomEvent('risk-nav:patch-coverage', { detail: patchState }));
}
window.addEventListener('risk-nav:dataset', event => { patchState.dataset = event.detail; patchState.filters = {}; q('#patchSearch').value = ''; q('#patchStatusFilter').value = ''; renderCoverage(); });
if (window.riskPatchDataset) { patchState.dataset = window.riskPatchDataset; renderCoverage(); }
