import { inventory, distance, selectInventory, latestCatalog, marketplace, releaseTier } from './inventory.mjs';
import { normalizeFeed, analyze, activePatches, unique, coverage, libraryPurl, purl } from './catalog.mjs';
export const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const h = escapeHtml;
export const labels = { available: 'Available', observed: 'Patched artifact observed', candidate: 'Review applicability', unconfirmed: 'Evidence blocked', gap: 'No match', unknown: 'Unknown identity' };
const storageKey = 'risk-nav-patch-feeds:v1';
export const patchState = { dataset: null, feeds: [], filters: {}, lastResult: null, rows: [], loading: false, error: '', scope: null };
let refreshView = () => {}, cache = new Map(), initialized = false;
let inventoryView = 'all';
let catalogScope = 'all';
let releasePolicy = 'baseline';
let inventoryCache = null;
let redrawInventory = () => {};
let inventorySearch = '';
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
function message(text) { q('#patchMessage').textContent = text; q('#patchMessage').dataset.kind = text.startsWith('Loaded ')?'success':'notice'; }
function save() {
  try { localStorage.setItem(storageKey, JSON.stringify(patchState.feeds.map(({document,source,releaseSets,enabled,visible,name,loaded_at})=>({document,source,releaseSets,enabled,visible,name,loaded_at})))); }
  catch { message('Changes apply to this session; browser storage is unavailable or full.'); }
}
function changed() { inventoryCache=null; cache.clear(); renderSources(); refreshView(); window.dispatchEvent(new CustomEvent('risk-nav:patch-coverage',{detail:patchState})); }
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
    const status=!purl(libraryPurl(lib))?'unknown':result.adopted.length?'observed':result.available.length?'available':result.candidates.length?'candidate':result.other.length?'unconfirmed':'gap';
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
  return `<span class="patch-badge patch-${displayStatus}">${h(matches.length?labels[displayStatus]:['gap','unknown'].includes(r.status)?labels[r.status]:'Hidden source coverage')}</span>${providers.length?`<span class="small patch-providers">${h(providers.join(', '))}</span>`:''}`;
}
function matchesFilter(lib) {const status=patchState.filters.status;return !status||(status==='opportunity'?['available','candidate'].includes(resultFor(lib).status):status===resultFor(lib).status);}
function detail(lib) {
  const r=resultFor(lib),matches=visibleMatches(r),targets=unique(matches.map(p=>p.target));
  return `<section class="patch-detail"><h3>Patch coverage</h3>${badge(lib)}<p>${r.covered.length} of ${(lib.cves||[]).length} listed findings have confirmed patch coverage.</p><p class="small">Published candidates require compatibility review. Observed artifacts are inventory evidence, not deployment verification.</p>${targets.map(target=>{const records=matches.filter(p=>p.target===target);return `<article class="patch-target"><strong>${h(target)}</strong><p>${h(unique(records.flatMap(p=>p.advisories)).join(', '))}</p><p class="small">${h(unique(records.map(p=>`${p.provider} · ${p.state} · ${p.status}`)).join('; '))}</p><details><summary>Source and release evidence</summary><pre>${h(JSON.stringify(records,null,2))}</pre></details></article>`;}).join('')||'<p>No visible matching evidence. Check source visibility or add an inventory.</p>'}<p><strong>Remaining findings:</strong> ${h(r.remaining.join(', ')||'None of the listed findings')}</p></section>`;
}
const ratio=(a,b)=>b?`${a} / ${b} (${Math.round(100*a/b)}%)`:'N/A';
function advisoryCards(ids) {
  const known=new Map();
  for(const lib of patchState.scope?.libraries || [])for(const cve of lib.cves || [])known.set(cve.cve_id,cve);
  return `<div class="patch-advisories">${ids.map(id=>{
    const cve=known.get(id);
    const external=/^CVE-\d{4}-\d+$/.test(id)?`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}`:/^GHSA-[a-z0-9-]+$/i.test(id)?`https://github.com/advisories/${encodeURIComponent(id)}`:null;
    const description=cve?.summary || cve?.description || '';
    const tooltip=[description,cve?.cvss!=null?`CVSS ${cve.cvss}`:'',cve?.kev?'Known exploited vulnerability':''].filter(Boolean).join(' · ');
    const action=cve?`<button class="cve-link" data-open-cve="${h(id)}" title="${h(tooltip || 'Open estate CVE details')}">${h(id)}</button>`:external?`<a href="${h(external)}" target="_blank" rel="noreferrer" title="Open public advisory">${h(id)}</a>`:`<strong>${h(id)}</strong>`;
    return `<span class="patch-advisory">${action}</span>`;
  }).join('')}</div>`;
}
function estateCard(item) {
  const projects=new Map((patchState.scope?.consumer_projects||[]).map(p=>[p.id,p]));
  const ids=unique(item.estateMatches.flatMap(m=>m.lib.consumer_project_ids||[]));
  const status=item.exactUse?'Exact patch found':item.sameLineVersions.length?'Same minor line':item.estateMatches.length?'Different minor line':'Outside selected inventory';
  return `<section class="patch-estate"><div class="patch-market-top"><h4>In your estate</h4><span class="patch-badge ${item.exactUse?'patch-observed':item.sameLineVersions.length?'patch-candidate':''}">${status}</span></div><div class="patch-estate-stats"><div><strong>${ids.length}</strong><span>applications</span></div><div><strong>${item.estateVersions.length}</strong><span>versions found</span></div></div>${item.estateMatches.length?item.estateMatches.map(({identity,lib})=>{
    const consumers=unique(lib.consumer_project_ids||[]);
    const direct=new Set(lib.direct_consumer_project_ids||[]);
    return `<details class="patch-consumers"><summary><span class="patch-coordinate">${h(purl(identity)?.version)}</span> <span class="small">· ${consumers.length} applications</span></summary><p><button class="ghost" data-open-library="${h(lib.id)}" title="Inspect this library and its dependency evidence">Inspect library details ↗</button></p><ul>${consumers.map(id=>{
      const project=projects.get(id),label=project?.project_ref||project?.proj||id;
      return `<li><span>${h(label)}</span><span class="patch-badge">${direct.has(id)?'Direct':'Transitive'}</span></li>`;
    }).join('')||'<li>No consumer application evidence in this scope.</li>'}</ul></details>`;
  }).join(''):'<p>No package observation in the selected scope.</p>'}<p class="small">Expand a version to see who uses it. Package presence does not prove patch applicability or deployment. Partial inventories may omit consumers.</p></section>`;
}
function libraryVersions(lib) {
  const identity=libraryPurl(lib), parsed=purl(identity);
  if(!parsed)return '';
  const feeds=patchState.feeds.filter(feed=>feed.enabled && feed.visible!==false).map(feed=>({...feed,patches:feed.patches.filter(p=>p.provider==='OSERA' && purl(p.target)?.key===parsed.key)}));
  const rows=latestCatalog(inventory({libraries:[]},feeds)).filter(row=>{
    const tier=releaseTier(identity,row.target);
    return tier===0 || tier===1;
  });
  if(!rows.length)return '';
  const all=activePatches(patchState.feeds);
  return `<section class="patch-library-versions"><h4>OSERA patched versions</h4><p class="small">Latest published OSERA patch on the current minor line. Published fixes are separate from the upstream safety assessment and do not prove deployment or compatibility.</p>${rows.map(row=>{
    const match=coverage(identity,(lib.cves||[]).map(c=>c.cve_id),all);
    const observed=match.adopted.some(p=>p.target===row.target);
    const applicable=match.available.some(p=>p.target===row.target);
    const blocked=match.other.some(p=>p.target===row.target);
    const tier=releaseTier(identity,row.target);
    return `<div class="patch-target"><div class="patch-market-top"><strong class="patch-coordinate">${h(parsed.version)} → ${h(purl(row.target).version)}</strong><span class="patch-badge ${blocked?'patch-unconfirmed':observed?'patch-observed':'patch-candidate'}">${blocked?'Evidence conflict · review required':observed?'Exact artifact observed':applicable?'Applicable fix':'Applicability review needed'}</span></div><p>${tier===0?'Current baseline backpatch':'Later patch baseline within the same minor line'} · OSERA</p><div class="small">Published fixes</div>${advisoryCards(row.advisories)}<details><summary>Release evidence</summary><pre>${h(JSON.stringify(row.records,null,2))}</pre></details></div>`;
  }).join('')}</section>`;
}
function catalogDetail(item) {
  const identity=purl(item.target);
  const visibleIds=new Set(patchState.feeds.filter(f=>f.visible!==false).map(f=>f.id));
  const records=item.records.filter(r=>visibleIds.has(r.feed_id));
  return `<section class="patch-detail"><span class="patch-badge">Published patch · ${h(item.line)} line</span><h3>${h(identity.name)}</h3><p>${h(item.providers.join(', '))}</p><h4>Latest published version in this minor line</h4><p class="patch-coordinate">${h(identity.version)}</p><p class="small">${h(item.target)}</p>
  <h4>Published fixes (${item.advisories.length})</h4>${advisoryCards(item.advisories)}
  ${estateCard(item)}
  <details><summary>Release-set artifacts (${item.companions.length})</summary><ul>${item.companions.map(c=>`<li>${h(c)}</li>`).join('')}</ul></details>
  <details><summary>Published source evidence</summary><pre>${h(JSON.stringify(records,null,2))}</pre></details></section>`;
}
function inventoryDetail(item) {
  if(item.catalogEntry)return catalogDetail(item);
  const identity = purl(item.target);
  const projectNames = new Map((patchState.scope?.consumer_projects || []).map(p => [p.id, p.name || p.id]));
  const observed = new Set(item.adopted.map(r => r.key));
  const eligible = new Set(item.available.map(r => r.key));
  const candidates = new Set(item.candidates.map(r => r.key));
  const residual = row => {
    // Credit only this target's assertions, not other available patches.
    const result = coverage(row.identity, row.advisories, activePatches(patchState.feeds).filter(p=>p.target===item.target));
    return result.remaining.join(', ') || 'None of the listed findings';
  };
  const visibleIds = new Set(patchState.feeds.filter(f=>f.visible!==false).map(f=>f.id));
  const visibleRecords = item.records.filter(r=>visibleIds.has(r.feed_id));
  const observationKeys = new Set(item.observations.map(row=>row.key));
  const related = (patchState.inventory || []).filter(other => purl(other.target)?.key === identity?.key && [...other.available,...other.candidates].some(row=>observationKeys.has(row.key)) && other.records.some(r=>visibleIds.has(r.feed_id)));
  return `<section class="patch-detail"><h3>${h(identity?.name || item.target)}</h3><p><strong>Target ${h(identity?.version)}</strong> · ${h(item.providers.join(', '))}</p>
    <p>${item.adopted.length + item.available.length ? `${item.adopted.length} of ${item.adopted.length + item.available.length} confirmed eligible component instances observed; ${item.available.length} remaining.` : "Adoption: N/A until applicability is confirmed or an exact target is observed."} ${item.candidates.length} require applicability review.</p>
    <p class="small">Adoption means an exact artifact in inventory, not verified deployment. Version distance is an effort hint, not compatibility evidence.</p>
    <h4>Adoption effort</h4><p>${h(item.efforts.join(' · ') || 'Outside the scoped estate · needs assessment')}</p>
    <p>${item.projects.length} affected applications · ${item.observations.filter(r=>!r.direct).length} transitive instances (assess parent or dependency-management changes).</p>
    <details><summary>Release-set artifacts (${item.companions.length})</summary><p class="small">Review these together; the feed does not establish that every artifact must change.</p><ul>${item.companions.map(c=>`<li>${h(c)}</li>`).join('')}</ul></details>
    <h4>Published fixes</h4>${advisoryCards(item.advisories)}
    <details><summary>Estate adoption and remaining findings</summary>${item.observations.length ? `<ul class="list">${item.observations.map(row=>`<li><strong>${h(projectNames.get(row.project)||row.project)}</strong> · ${h(purl(row.identity)?.version)} → ${h(identity?.version)}<br>${observed.has(row.key)?'Adopted (observed)':eligible.has(row.key)?'Ready to adopt':candidates.has(row.key)?'Needs applicability review':'Conflicting or blocked evidence'} · ${row.direct?'Direct':'Transitive'}<br><span class="small">${h(distance(row.identity,item.target))}<br>${observed.has(row.key)?'Remaining':eligible.has(row.key)?'Remaining if adopted':'Current findings'}: ${h(observed.has(row.key)||eligible.has(row.key)?residual(row):row.advisories.join(', ')||'None listed')}</span></li>`).join('')}</ul>`:'<p>No matching observations in this estate scope.</p>'}</details>
    <h4>Latest releases · published patch targets</h4><p class="small">Latest suggested target per observed version and provider under the selected upgrade scope. Previously adopted versions remain in the adoption view, not in these suggestions. Same major/minor highlights a review opportunity; it does not establish applicability. Feed timestamps describe publication evidence, not version ordering.</p>
    ${related.map(other=>`<div class="patch-target"><strong>${h(purl(other.target)?.version)}</strong> · ${h(other.providers.join(', '))}<br>${h(unique(item.observations.map(row=>distance(row.identity,other.target))).join(' · ')||'No estate version to compare')}<br><span class="small">${other.advisories.length} published advisory assertions · ${other.available.length} ready · ${other.adopted.length} observed</span></div>`).join('')}
    <details><summary>Source evidence</summary><pre>${h(JSON.stringify(visibleRecords,null,2))}</pre></details></section>`;
}
function renderMode(libs,scope,selected,onSelect) {
  redrawInventory=()=>{const item=renderMode(libs,scope,selected,onSelect);onSelect(item);};
  patchState.scope={...scope,libraries:libs};
  const scopeKey=JSON.stringify(libs.map(lib=>[lib.id,lib.consumer_project_ids,lib.direct_consumer_project_ids]));
  if(!inventoryCache || inventoryCache.key!==scopeKey)inventoryCache={key:scopeKey,all:inventory(patchState.scope,patchState.feeds),selected:new Map()};
  const all = inventoryCache.all;
  patchState.inventory = all;
  const visibleIds = new Set(patchState.feeds.filter(f=>f.visible!==false).map(f=>f.id));
  for(const row of all) {
    const shown=row.records.filter(r=>visibleIds.has(r.feed_id));
    row.providers=unique(shown.map(r=>r.provider));
    row.companions=unique(shown.flatMap(r=>r.companions||[]));
    row.advisories=unique(shown.flatMap(r=>r.advisories));
  }
  if(!inventoryCache.selected.has(releasePolicy))inventoryCache.selected.set(releasePolicy,selectInventory(all,releasePolicy));
  const estate = inventoryCache.selected.get(releasePolicy);
  patchState.inventory = estate;
  const choices = {all:'Browse patches',estate:'Estate opportunities',available:'Ready to adopt',candidates:'Needs review',adopted:'Adopted'};
  if(!q('#inventoryViews')) {
    const controls=document.createElement('div');controls.id='inventoryViews';controls.innerHTML=`<div class="patch-actions" role="group" aria-label="Patch inventory views">${Object.entries(choices).map(([key,label])=>`<button data-inventory-view="${key}">${label}</button>`).join('')}</div><label id="upgradeScopeControl">Upgrade scope <select id="releasePolicy"><option value="baseline">Current baseline only</option><option value="patch">Allow later patches in same minor</option><option value="minor">Allow newer minor as fallback</option></select></label><p id="upgradeScopeHelp" class="small">Latest target only. Prefer the current baseline (1.2.4 → 1.2.4.x); broader moves are fallbacks when no closer target exists. No downgrades or major upgrades.</p><label id="catalogScopeControl">Estate relevance <select id="catalogScope"><option value="all">Show everything</option><option value="present">Package in my estate</option><option value="absent">Package outside my estate</option><option value="line">Same minor line in my estate</option><option value="adopted">Exact patch in my estate</option></select></label><label>Find a patch <input id="inventorySearch" type="search" placeholder="Package, version, CVE or provider"></label>`;
    q('#patchMetrics').before(controls);
    controls.querySelectorAll('[data-inventory-view]').forEach(button=>button.onclick=()=>{inventoryView=button.dataset.inventoryView;redrawInventory();});
    q('#catalogScope').onchange=event=>{catalogScope=event.target.value;redrawInventory();};
    q('#releasePolicy').onchange=event=>{releasePolicy=event.target.value;redrawInventory();};
    q('#inventorySearch').oninput=event=>{inventorySearch=event.target.value;redrawInventory();};
  }
  q('#inventoryViews').hidden=false;
  const browsing=inventoryView==='all';
  q('#upgradeScopeControl').hidden=browsing;q('#upgradeScopeHelp').hidden=browsing;q('#catalogScopeControl').hidden=!browsing;
  for(const button of q('#inventoryViews').querySelectorAll('button'))button.setAttribute('aria-pressed',String(button.dataset.inventoryView===inventoryView));
  q('#patchMetrics').hidden=false;q('#patchScope').hidden=false;
  q('#patchMetrics').innerHTML=`<div class="patch-metrics"><div><strong>${estate.filter(r=>r.available.length).length}</strong><br>Targets ready to adopt</div><div><strong>${estate.filter(r=>r.candidates.length).length}</strong><br>Targets needing review</div><div><strong>${estate.filter(r=>r.adopted.length).length}</strong><br>Targets observed in estate</div></div>`;
  q('#patchScope').textContent=`Inventory ${scope.meta?.extracted_at||'date unknown'}. ${scope.meta?.inventory_complete===true?'Source declares complete inventory.':'Partial inventory: observed adoption is a lower bound.'} Totals include enabled hidden sources; rows show targets with visible evidence. Counts are patch targets, not unique CVEs or applications. A target can be adopted and still have remaining opportunities. Latest published patches includes targets outside the estate; estate observations follow the main filters.`;
  if(browsing) {
    if(!inventoryCache.catalog)inventoryCache.catalog=marketplace(all,patchState.scope);
    const catalog=inventoryCache.catalog.filter(row=>row.records.some(r=>visibleIds.has(r.feed_id)));
    const relevant=catalog.filter(row=>catalogScope==='all'||(catalogScope==='present'?row.estateMatches.length:catalogScope==='absent'?!row.estateMatches.length:catalogScope==='line'?row.sameLineVersions.length:row.exactUse));
    const rows=relevant.filter(row=>`${row.target} ${row.advisories.join(' ')} ${row.providers.join(' ')}`.toLowerCase().includes(inventorySearch.toLowerCase()));
    patchState.rows=rows;
    q('#patchMetrics').innerHTML=`<div class="patch-metrics"><div><strong>${unique(catalog.map(row=>purl(row.target)?.key)).length}</strong><br>Published packages</div><div><strong>${catalog.length}</strong><br>Latest package / minor-line listings</div><div><strong>${catalog.filter(row=>row.estateMatches.length).length}</strong><br>Listings for packages in your estate</div></div>`;
    q('#patchScope').textContent=`Browse the latest published patch per package, provider and minor line. Historical builds are omitted. Estate relevance uses package identity, not upgrade eligibility. Inventory ${scope.meta?.extracted_at||'date unknown'}${scope.meta?.inventory_complete===true?'': ' · partial inventory; absence is unconfirmed'}. Search and relevance narrow listings; summary counts cover the full visible catalog.`;
    document.getElementById('mainTable').hidden=true;
    const grid=document.getElementById('dashboardView');grid.hidden=false;
    grid.innerHTML=`<section class="patch-market"><h3>Published patch catalog</h3><p class="small">Explore maintained version lines and their published fixes. Select a package for release evidence and estate context.</p><div class="patch-market-grid">${rows.map((row,i)=>`<button class="patch-market-card ${row.id===selected?'selected':''}" data-market-row="${i}" aria-label="Inspect ${h(row.target)}"><span class="patch-market-top"><span>${h(row.providers.join(', '))}</span><span class="patch-badge">${h(row.line)} line</span></span><strong>${h(purl(row.target).name.split('/').pop())}</strong><span class="small">${h(purl(row.target).name)}</span><span class="patch-coordinate">${h(purl(row.target).version)}</span><span>${row.advisories.length} published advisory IDs</span><span class="patch-market-presence">${row.exactUse?'Exact patch in estate':row.sameLineVersions.length?'Same minor line in estate':row.estateMatches.length?'Package in estate · different line':'Outside selected inventory'}</span></button>`).join('')||'<p>No published patches match these filters.</p>'}</div></section>`;
    grid.querySelectorAll('[data-market-row]').forEach(button=>button.onclick=()=>{const row=rows[Number(button.dataset.marketRow)];selected=row.id;grid.querySelectorAll('[data-market-row]').forEach(b=>b.classList.toggle('selected',b===button));onSelect(row);});
    document.getElementById('rowCount').textContent=`${rows.length} published listings`;
    return rows.find(row=>row.id===selected)||rows[0]||null;
  }
  const rows=(inventoryView==='estate'?estate:estate.filter(row=>row[inventoryView].length)).filter(row=>row.records.some(r=>visibleIds.has(r.feed_id))).filter(row=>`${row.target} ${row.advisories.join(' ')} ${row.providers.join(' ')}`.toLowerCase().includes(inventorySearch.toLowerCase()));
  patchState.rows=rows;
  const table=document.getElementById('mainTable');table.hidden=false;document.getElementById('dashboardView').hidden=true;
  document.getElementById('tableHead').innerHTML=['Patch target / provider','Current → target','Adoption (instances)','Adoption effort','Published fixes'].map(t=>`<th>${t}</th>`).join('');
  const body=document.getElementById('tableBody');body.innerHTML=rows.map((row,i)=>`<tr tabindex="0" aria-label="Inspect ${h(row.target)}" data-patch-row="${i}" class="${row.id===selected?'sel':''}"><td><strong>${h(purl(row.target)?.name)}</strong><br>${h(row.providers.join(', '))}</td><td>${h(row.versions.join(', ')||'Unknown version')} → <strong>${h(purl(row.target)?.version)}</strong></td><td>${row.adopted.length+row.available.length ? `${row.adopted.length} / ${row.adopted.length+row.available.length} observed` : 'N/A · applicability unconfirmed'}<br>${row.available.length} ready · ${row.candidates.length} review${row.blocked.length?` · ${row.blocked.length} blocked`:''}</td><td>${h(row.efforts.join(' · ')||'Needs assessment')}<br><span class="small">${row.projects.length} applications</span></td><td>${row.advisories.length} advisory IDs</td></tr>`).join('')||'<tr><td colspan="5">No patches in this view. Try a broader upgrade scope, Needs review, or Latest published patches.</td></tr>';
  body.querySelectorAll('[data-patch-row]').forEach(tr=>{tr.onclick=()=>{selected=rows[Number(tr.dataset.patchRow)].id;body.querySelectorAll("[data-patch-row]").forEach(row=>row.classList.toggle("sel",row===tr));onSelect(rows[Number(tr.dataset.patchRow)]);};tr.onkeydown=event=>{if(['Enter',' '].includes(event.key)){event.preventDefault();tr.click();}};});
  document.getElementById('rowCount').textContent=`${rows.length} patch targets`;
  return rows.find(row=>row.id===selected)||rows[0]||null;
}

window.riskPatches={libraryVersions,inventoryDetail,badge,detail,matchesFilter,renderMode,resultFor,setView(mode,callback){refreshView=callback;if(q('#inventoryViews'))q('#inventoryViews').hidden=mode!=='patch-coverage';host.dataset.mode=mode;q('#patchStatusFilter').closest('.patch-actions').hidden=mode==='patch-coverage';q('.patch-heading strong').textContent=mode==='libraries'?'Patch sources':'Patch inventory';host.hidden=!['libraries','patch-coverage'].includes(mode);q('#patchMetrics').hidden=mode!=='patch-coverage';q('#patchScope').hidden=mode!=='patch-coverage';},open(){window.dispatchEvent(new CustomEvent('risk-nav:open-patches'));}};
window.addEventListener('risk-nav:dataset',event=>{patchState.dataset=event.detail;inventoryCache=null;cache.clear();patchState.filters={};q('#patchStatusFilter').value='';window.dispatchEvent(new CustomEvent('risk-nav:patch-coverage',{detail:patchState}));});
if(window.riskPatchDataset)patchState.dataset=window.riskPatchDataset;
renderSources();
window.dispatchEvent(new CustomEvent('risk-nav:patch-ready'));
if(autoRefresh&&!initialized){initialized=true;refreshOsera();}
