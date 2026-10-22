import { normalizeFeed, analyze, activePatches, unique, coverage, libraryPurl } from './catalog.mjs';
export const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const h = escapeHtml;
export const labels = { available: 'Available', observed: 'Patched artifact observed', candidate: 'Review applicability', unconfirmed: 'Evidence blocked', gap: 'No match', unknown: 'Unknown identity' };
const storageKey = 'risk-nav-patch-feeds:v1';
export const patchState = { dataset: null, feeds: [], filters: {}, lastResult: null, rows: [], loading: false, error: '', scope: null };
let refreshView = () => {}, cache = new Map(), initialized = false;
let autoRefresh = true;
try { autoRefresh = localStorage.getItem('risk-nav-osera-auto-refresh') !== 'false'; } catch {}
try {
  patchState.feeds = JSON.parse(localStorage.getItem(storageKey) || '[]').map(s => ({ ...normalizeFeed(s.document, s.source, s.releaseSets),
    enabled: s.enabled !== false, visible: s.visible !== false, name: s.name || '', loaded_at: s.loaded_at || 'unknown', document: s.document, releaseSets: s.releaseSets }));
} catch { patchState.error = 'Saved sources could not be restored. Import them again or refresh OSERA.'; }
const host = document.getElementById('patchCoverage');
host.innerHTML = `<div class="patch-heading"><div><strong>Patch coverage</strong><span id="patchFeedStatus" class="small" role="status"></span></div><div class="patch-actions"><button id="loadOsera">Refresh OSERA</button><button id="managePatchSources" aria-expanded="false">Manage sources</button></div></div>
<div id="patchSourcesSummary" class="small"></div>
<div id="patchSourcesManager" hidden><h3>Patch sources</h3><p class="small">Enabled sources contribute to matching and totals. Visible sources appear in badges and evidence. Hidden sources still count.</p><div id="patchSources"></div>
<div class="patch-actions"><label>Import supplemental inventory <input id="patchFile" type="file" accept=".json,application/json"></label><label>Feed URL <input id="patchUrl" type="url" placeholder="https://…/catalog.json"></label><button id="loadPatchUrl">Add URL</button></div>
<label><input id="autoOsera" type="checkbox"> Refresh OSERA automatically at startup</label><p class="small">Uploads stay in this browser. URL feeds receive a download request, never your estate inventory.</p></div>
<p id="patchMessage" role="status" aria-live="polite"></p>
<div class="patch-actions"><label>Show <select id="patchStatusFilter"><option value="">All libraries</option><option value="opportunity">Has patch opportunity</option>${Object.entries(labels).map(([k,v])=>`<option value="${k}">${v}</option>`).join('')}</select></label><span class="small">Uses the main library filters and selected estate.</span></div>
<div id="patchMetrics" hidden></div><p id="patchScope" class="small" hidden></p><div id="patchRequestMount"></div>`;
const q = selector => host.querySelector(selector);
function message(text) { q('#patchMessage').textContent = text; }
function save() {
  try { localStorage.setItem(storageKey, JSON.stringify(patchState.feeds.map(({document,source,releaseSets,enabled,visible,name,loaded_at})=>({document,source,releaseSets,enabled,visible,name,loaded_at})))); }
  catch { message('Changes apply to this session; browser storage is unavailable or full.'); }
}
function changed() { cache.clear(); renderSources(); refreshView(); window.dispatchEvent(new CustomEvent('risk-nav:patch-coverage',{detail:patchState})); }
export function installFeed(document, source, releaseSets = null) {
  const parsed = normalizeFeed(document,source,releaseSets);
  const previous = patchState.feeds.find(f=>f.id===parsed.id);
  const feed={...parsed, document,releaseSets,visible:previous?.visible!==false,enabled:previous?.enabled!==false,name:previous?.name||''};
  patchState.feeds=patchState.feeds.filter(f=>f.id!==feed.id).concat(feed);
  patchState.error='';save();changed();message(`Loaded ${feed.patches.length} records. ${feed.errors.length} invalid records excluded.`);
}
async function fetchJson(url) {
  const parsed=new URL(url);if(parsed.protocol!=='https:')throw new Error('Use an HTTPS feed URL.');
  const response=await fetch(parsed,{credentials:'omit',signal:AbortSignal.timeout(20000)});
  if(!response.ok)throw new Error(`Feed request failed (${response.status}).`);
  return response.json();
}
export async function refreshOsera() {
  if(patchState.loading)return;
  patchState.loading=true;renderSources();
  try { const [vex,sets]=await Promise.all([fetchJson('https://feed.finos.org/openvex.json'),fetchJson('https://feed.finos.org/sets.json')]);installFeed(vex,'https://feed.finos.org/openvex.json',sets); }
  catch(error){patchState.error=`${error.message} Cached evidence retained; it may be stale.`;message(patchState.error);}
  finally{patchState.loading=false;renderSources();refreshView();}
}
q('#loadOsera').onclick=refreshOsera;
q('#managePatchSources').onclick=()=>{const panel=q('#patchSourcesManager');panel.hidden=!panel.hidden;q('#managePatchSources').setAttribute('aria-expanded',String(!panel.hidden));};
q('#autoOsera').checked=autoRefresh;
q('#autoOsera').onchange=event=>{autoRefresh=event.target.checked;try{localStorage.setItem('risk-nav-osera-auto-refresh',String(autoRefresh));}catch{};};
q('#loadPatchUrl').onclick=async event=>{
  const button=event.target;button.disabled=true;
  try{const url=q('#patchUrl').value.trim();installFeed(await fetchJson(url),url);}catch(error){message(error.message+' Previous sources retained.');}finally{button.disabled=false;}
};
q('#patchFile').onchange=async event=>{
  const file=event.target.files[0];if(!file)return;
  try{if(file.size>10*1024*1024)throw new Error('Inventory exceeds the 10 MB limit.');const doc=JSON.parse(await file.text());installFeed(doc.openvex||doc,file.name,doc.openvex?doc.release_sets:null);}catch(error){message(error.message);}
  event.target.value='';
};
q('#patchStatusFilter').onchange=event=>{patchState.filters.status=event.target.value;refreshView();};
function renderSources() {
  q('#loadOsera').disabled=patchState.loading;
  const os=patchState.feeds.find(f=>f.id==='https://feed.finos.org/openvex.json');
  q('#patchFeedStatus').textContent=patchState.loading?'Refreshing OSERA…':patchState.error?(os?'Refresh unavailable · cached results':'OSERA unavailable'):os?`OSERA snapshot ${os.generated_at} · checked ${os.loaded_at}`:'OSERA not loaded';
  q('#patchSourcesSummary').textContent=patchState.feeds.map(f=>`${f.name||f.provider}: ${!f.enabled?'disabled':f.visible?'visible':'hidden (included in totals)'}`).join(' · ')||'No sources loaded yet';
  q('#patchSources').innerHTML=patchState.feeds.map((f,i)=>`<div class="patch-source"><div class="patch-actions"><label>Source name <input data-name="${i}" value="${h(f.name||f.provider)}"></label><label><input type="checkbox" data-enabled="${i}" ${f.enabled?'checked':''}> Enabled</label><label><input type="checkbox" data-visible="${i}" ${f.visible?'checked':''}> Visible</label><button data-refresh="${i}" ${/^https:\/\//.test(f.source)?"":"disabled"}>Refresh</button><button data-remove="${i}">Remove</button></div><div class="small">${h(f.provider)} · ${f.patches.length} records · version ${h(f.version)} · ${h(f.generated_at)}<br>${h(f.source)}</div>${f.errors.length?`<details><summary>${f.errors.length} validation errors</summary><pre>${h(f.errors.join('\n'))}</pre></details>`:''}</div>`).join('');
  for(const key of ['enabled','visible','name'])q('#patchSources').querySelectorAll(`[data-${key}]`).forEach(input=>input.onchange=()=>{patchState.feeds[Number(input.dataset[key])][key]=key==='name'?input.value.trim():input.checked;save();changed();});
  q('#patchSources').querySelectorAll('[data-refresh]').forEach(button=>button.onclick=async()=>{const feed=patchState.feeds[Number(button.dataset.refresh)];if(feed.id==='https://feed.finos.org/openvex.json')return refreshOsera();button.disabled=true;try{installFeed(await fetchJson(feed.source),feed.source);}catch(error){message(error.message+' Previous source retained.');}finally{button.disabled=false;}});
  q('#patchSources').querySelectorAll('[data-remove]').forEach(button=>button.onclick=()=>{const removed=patchState.feeds.splice(Number(button.dataset.remove),1)[0];if(removed?.id==='https://feed.finos.org/openvex.json'){autoRefresh=false;q('#autoOsera').checked=false;try{localStorage.setItem('risk-nav-osera-auto-refresh','false');}catch{}}save();changed();});
}
function resultFor(lib) {
  if(!cache.has(lib.id)) {
    const result=coverage(libraryPurl(lib),(lib.cves||[]).map(c=>c.cve_id),activePatches(patchState.feeds));
    const status=result.adopted.length?'observed':result.available.length?'available':result.candidates.length?'candidate':result.other.length?'unconfirmed':'gap';
    cache.set(lib.id,{...result,status,library:lib});
  }
  return cache.get(lib.id);
}
function visibleMatches(result) { const ids=new Set(patchState.feeds.filter(f=>f.enabled&&f.visible).map(f=>f.id));return [...result.adopted,...result.available,...result.candidates,...result.other].filter(p=>ids.has(p.feed_id)); }
function badge(lib) {
  const r=resultFor(lib),matches=visibleMatches(r),providers=unique(matches.map(p=>patchState.feeds.find(f=>f.id===p.feed_id)?.name||p.provider));
  if(!patchState.feeds.some(f=>f.enabled))return '<span class="small">Sources not enabled</span>';
  const shown = ['adopted','available','candidates','other'].find(key=>r[key].some(p=>matches.includes(p)));
  const displayStatus = {adopted:'observed',available:'available',candidates:'candidate',other:'unconfirmed'}[shown] || r.status;
  return `<span class="patch-badge patch-${displayStatus}">${h(matches.length?labels[displayStatus]:r.status==='gap'?'No match':'Hidden source coverage')}</span>${providers.length?`<span class="small patch-providers">${h(providers.join(', '))}</span>`:''}`;
}
function matchesFilter(lib) {const status=patchState.filters.status;return !status||(status==='opportunity'?['available','candidate'].includes(resultFor(lib).status):status===resultFor(lib).status);}
function detail(lib) {
  const r=resultFor(lib),matches=visibleMatches(r),targets=unique(matches.map(p=>p.target));
  return `<section class="patch-detail"><h3>Patch coverage</h3>${badge(lib)}<p>${r.covered.length} of ${(lib.cves||[]).length} listed findings have confirmed patch coverage.</p><p class="small">Published candidates require compatibility review. Observed artifacts are inventory evidence, not deployment verification.</p>${targets.map(target=>{const records=matches.filter(p=>p.target===target);return `<article class="patch-target"><strong>${h(target)}</strong><p>${h(unique(records.flatMap(p=>p.advisories)).join(', '))}</p><p class="small">${h(unique(records.map(p=>`${p.provider} · ${p.state} · ${p.status}`)).join('; '))}</p><details><summary>Source and release evidence</summary><pre>${h(JSON.stringify(records,null,2))}</pre></details></article>`;}).join('')||'<p>No visible matching evidence. Check source visibility or add an inventory.</p>'}<p><strong>Remaining findings:</strong> ${h(r.remaining.join(', ')||'None of the listed findings')}</p></section>`;
}
const ratio=(a,b)=>b?`${a} / ${b} (${Math.round(100*a/b)}%)`:'N/A';
function renderMode(libs,scope,selected,onSelect) {
  patchState.scope=scope;
  const result=analyze({...scope,libraries:libs},patchState.feeds);patchState.lastResult=result;
  patchState.rows=libs;
  q('#patchMetrics').hidden=false;q('#patchScope').hidden=false;
  q('#patchMetrics').innerHTML=`<div class="patch-metrics"><div><strong>${libs.filter(l=>resultFor(l).available.length).length}</strong><br>Libraries with applicable fixes</div><div><strong>${libs.filter(l=>resultFor(l).candidates.length).length}</strong><br>Libraries to review</div><div><strong>${ratio(result.observed,result.eligible)}</strong><br>Patched / eligible instances</div></div>`;
  q('#patchScope').textContent=`${scope.meta?.scope_name||'Estate'} · inventory ${scope.meta?.extracted_at||'date unknown'} · ${result.totalProjects} scoped applications. ${scope.meta?.inventory_complete===true?'Source declares complete inventory.':'Partial inventory: adoption is a lower bound.'} Totals include enabled hidden sources and the current library filters. State selection narrows the rows only.`;
  const rows=libs.filter(matchesFilter);
  const table=document.getElementById('mainTable');table.hidden=false;document.getElementById('dashboardView').hidden=true;
  document.getElementById('tableHead').innerHTML=['Library / version','Patch coverage','Covered findings','Scoped projects'].map(t=>`<th>${t}</th>`).join('');
  const body=document.getElementById('tableBody');body.innerHTML=rows.map((lib,i)=>`<tr tabindex="0" aria-label="Inspect ${h(lib.proj)} ${h(lib.release)} patch coverage" data-patch-row="${i}" class="${lib.id===selected?'sel':''}"><td><strong>${h(lib.meta?lib.meta+':':'')}${h(lib.proj)}</strong><br><span class="small">${h(lib.release)}</span></td><td>${badge(lib)}</td><td>${resultFor(lib).covered.length} / ${(lib.cves||[]).length}</td><td>${unique(lib.consumer_project_ids||[]).length}</td></tr>`).join('');
  body.querySelectorAll('[data-patch-row]').forEach(tr=>{tr.onclick=()=>onSelect(rows[Number(tr.dataset.patchRow)]);tr.onkeydown=event=>{if(['Enter',' '].includes(event.key)){event.preventDefault();tr.click();}};});
  document.getElementById('rowCount').textContent=`${rows.length} libraries`;
  return rows.find(l=>l.id===selected)||rows[0]||null;
}
window.riskPatches={badge,detail,matchesFilter,renderMode,resultFor,setView(mode,callback){refreshView=callback;host.hidden=!['libraries','patch-coverage'].includes(mode);q('#patchMetrics').hidden=mode!=='patch-coverage';q('#patchScope').hidden=mode!=='patch-coverage';},open(){window.dispatchEvent(new CustomEvent('risk-nav:open-patches'));}};
window.addEventListener('risk-nav:dataset',event=>{patchState.dataset=event.detail;cache.clear();patchState.filters={};q('#patchStatusFilter').value='';window.dispatchEvent(new CustomEvent('risk-nav:patch-coverage',{detail:patchState}));});
if(window.riskPatchDataset)patchState.dataset=window.riskPatchDataset;
renderSources();
window.dispatchEvent(new CustomEvent('risk-nav:patch-ready'));
if(autoRefresh&&!initialized){initialized=true;refreshOsera();}
