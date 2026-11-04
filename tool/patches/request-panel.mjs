import { releaseTier, compareReleases } from './inventory.mjs';
import { patchState, escapeHtml as h } from './panel.mjs';
import { activePatches, purl, unique } from './catalog.mjs';
import { addRequest, requestFromLibrary, requestKey, validateRequest, normalizeWork, reviewRequest, impact, exportRequests, requestSummary, requestsFromAdoption } from './requests.mjs';
const mount = document.getElementById('patchRequestMount');
document.querySelector('.table-wrap').append(mount);
mount.hidden=true;
let scope = '', items = [], work = [], savedSnapshot = '', exported = '', editing = null, formDirty = false;
function patchEvidence(item, review) {
  const visible=[...review.available,...review.adopted,...review.candidates].filter(p=>patchState.feeds.some(f=>f.id===p.feed_id&&f.visible!==false));
  const targets=new Map();
  for(const patch of visible) {
    const tier=releaseTier(item.identity,patch.target);
    if(tier===null || tier>1)continue;
    const key=`${patch.provider}|${tier}`;
    const previous=targets.get(key);
    if(!previous || compareReleases(purl(patch.target).version,purl(previous.target).version)>0)targets.set(key,patch);
  }
  return [...targets.values()].map(p=>`<div class="patch-target"><span class="patch-badge">${h(p.provider)}</span> <strong>${h(purl(p.target)?.version)}</strong><p class="small">${releaseTier(item.identity,p.target)===0?'Current baseline':'Later patch in the same minor line'} · ${review.available.some(a=>a.target===p.target)?'Applicability confirmed':review.adopted.some(a=>a.target===p.target)?'Exact artifact observed':'Review applicability'}</p><p class="small">Published fixes: ${h(unique(visible.filter(a=>a.target===p.target).flatMap(a=>a.advisories)).join(', '))}</p></div>`).join('');
}
function snapshot() { return JSON.stringify([patchState.dataset?.meta?.extracted_at,patchState.feeds.map(f=>[f.id,f.version,f.generated_at,f.enabled])]); }
function storageKey() { return `risk-nav-osera-request-cart:v1:${encodeURIComponent(scope)}`; }
function note(text) { const el=mount.querySelector('#requestMessage'); if(el)el.textContent=text; }
function save() {
  try { localStorage.setItem(storageKey(),JSON.stringify({items,work,savedSnapshot,exported})); }
  catch { note('Selections remain in this session, but browser storage is unavailable.'); }
}
function loadScope() {
  const next=String(patchState.dataset?.meta?.scope_name || 'unnamed');
  if(scope===next)return;
  scope=next; formDirty=false; items=[];work=[];savedSnapshot='';exported='';editing=null;
  try {
    const saved=JSON.parse(localStorage.getItem(storageKey())||'{}');
    items=(saved.items||[]).reduce((acc,item)=>addRequest(acc,validateRequest(item)),[]);
    work=normalizeWork({schema_version:1,requests:saved.work||[]});
    savedSnapshot=String(saved.savedSnapshot||'');exported=String(saved.exported||'');
  } catch { items=[];work=[]; }
}
function openCart() {
  window.dispatchEvent(new CustomEvent('risk-nav:open-requests'));

}
function addLibrary(lib) {
  try {
    items=addRequest(items,requestFromLibrary(lib),activePatches(patchState.feeds));
    savedSnapshot=snapshot();exported='';render();save();openCart();note('Draft added. Review existing fixes below before downloading.');
  } catch(error) { openCart();note(error.message); }
}
function editForm(item=null) {
  const form=mount.querySelector('form'); form.reset();formDirty=false;
  editing=item?requestKey(item):null;
  if(item)for(const field of ['identity','precision','line','rationale','incompatibility'])form.elements[field].value=item[field]||'';
  if(item){form.elements.advisories.value=item.advisories.join(', ');form.elements.remediation.value=item.remediation.join(',');}
  mount.querySelector('#requestEditorTitle').textContent=item?`${purl(item.identity).name} · ${item.line}`:'Manual draft';
  mount.querySelector('#requestSave').textContent=item?'Save changes':'Save draft';
  mount.querySelector('#requestEditor').open=true;
  form.elements.rationale.focus();
}
function download(name,content,type) {
  const url=URL.createObjectURL(new Blob([content],{type})),a=document.createElement('a');
  a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
}
function render(preserveDraft = false) {
  if(!patchState.dataset)return;
  const previousScope = scope;
  const form = mount.querySelector('form');
  const draft = preserveDraft && form ? Object.fromEntries(new FormData(form)) : null;
  const editKey = editing;
  loadScope();
  const editorOpen=mount.querySelector('#requestEditor')?.open||false;
  const advancedOpen=mount.querySelector('#requestAdvanced')?.open||false;
  const count=impact(items,patchState.dataset,patchState.feeds);
  const waiting=patchState.loading;
  mount.innerHTML=`<section class="request-workspace"><div class="request-heading"><div><h2>Patch request drafts</h2><p>Review existing fixes, then prepare a draft for missing coverage.</p></div><span class="patch-badge">Saved in this browser · not submitted</span></div>
    <ol class="request-steps"><li>Select a library</li><li>Review fixes &amp; explain the gap</li><li>Download a draft</li></ol>
    <div class="patch-actions"><button id="requestChooseLibrary" class="primary">Choose a library</button><button id="requestBrowsePatches">Browse existing patches</button><button id="requestManual">Enter a package manually</button></div>
    <div class="patch-request-feed" role="status">${waiting?'Checking latest patch feeds…':patchState.error?h(patchState.error):`${patchState.feeds.filter(f=>f.enabled).length} enabled sources checked · ${h(patchState.feeds.filter(f=>f.enabled).map(f=>`${f.name||f.provider}: ${f.generated_at}`).join(' · '))||'No patch sources loaded; coverage is unknown.'}`}</div>
    <p>Nothing is sent to OSERA from this screen. Download a draft to share through your agreed request channel; there is no connected submission service yet.</p>
    <p class="small">Scope: ${h(scope)} · ${items.length} requests · ${count.applications} unique applications · ${count.instances} observed component instances · ${count.direct} direct / ${count.transitive} transitive applications (may overlap) · ${count.advisories} observed advisories · ${count.kev} KEVs. Potential impact only; partial inventories undercount.</p>
    ${savedSnapshot && savedSnapshot!==snapshot()?'<p class="patch-warning">Evidence changed since this draft was saved. Review the updated coverage before downloading.</p>':''}
    ${exported?`<p class="small">Last downloaded: ${h(exported)} · not submitted.</p>`:''}
    <details class="request-tools"><summary>Optional: check existing OSERA work</summary><p>${work.length} imported references. ${work.length?'Verify their linked status before requesting duplicate work.':'No backlog connected. Existing requests are unknown.'}</p><label>Import work references <input id="requestWorkFile" type="file" accept=".json,application/json"></label></details>
    <div id="requestMessage" role="status" aria-live="polite"></div>
    <div class="request-list">${items.map((item,index)=>{
      const r=reviewRequest(item,patchState.dataset,patchState.feeds,work);
      return `<article class="patch-source request-card"><div class="request-heading"><h3>${h(purl(item.identity)?.name)} <span class="small">${h(item.line)}</span></h3><span class="patch-badge">${!r.remaining.length?'Existing coverage found':r.candidates.length?'Review a published fix':'Missing coverage draft'}</span></div><p><strong>${!r.remaining.length?'An existing fix covers these advisories. Remove this draft, or explain why that fix cannot be used.':`Requested fixes: ${h(r.remaining.join(', '))}`}</strong></p>
      <details><summary>Coverage counts and findings</summary><p class="small">Requested: ${h(item.advisories.join(', '))}. ${unique(r.available.map(p=>p.target)).length} applicable targets · ${unique(r.adopted.map(p=>p.target)).length} observed targets · ${unique(r.candidates.map(p=>p.target)).length} published candidates across all lines. ${r.staleAdvisories.length?'Not present in current observed findings: '+h(r.staleAdvisories.join(', '))+'. Check manual/stale requests.':''}</p></details>
      ${r.candidates.length?'<p class="patch-warning">A published fix may address this need. Check the version and compatibility; a published candidate is not a confirmed upgrade.</p>':''}
      ${patchEvidence(item,r)}
      <details><summary>All existing patch / work evidence</summary><p class="small">Only visible source details are shown; enabled hidden sources still contribute to coverage checks.</p><pre>${h(JSON.stringify([...r.available,...r.adopted,...r.candidates].filter(p=>patchState.feeds.some(f=>f.id===p.feed_id&&f.visible)).map(p=>({target:p.target,provider:p.provider,advisories:p.advisories,evidence:p.evidence,release_set:p.release_set})),null,2))}</pre>${r.work.map(w=>`<p><a href="${h(w.url)}" target="_blank" rel="noreferrer">${h(w.status)}: ${h(w.line)}</a> · ${h(w.advisories.join(', '))}</p>`).join('')||'<p>No matching imported work reference.</p>'}</details>
      ${item.rationale?`<p><strong>Why this patch is needed:</strong> ${h(item.rationale)}</p>`:''}
      ${item.incompatibility?`<p>Existing-fix exception: ${h(item.incompatibility)}</p>`:''}
      <button data-edit="${index}">Edit draft / explain gap</button> <button data-delete="${index}">Remove</button></article>`;
    }).join('')||'<div class="request-empty"><h3>Start with a library from your inventory</h3><p>Its package, installed version and known CVEs will be filled in for you. Review existing fixes before asking for a new patch.</p></div>'}</div>
    <details id="requestEditor" ${editorOpen && scope===previousScope?'open':''}><summary>Edit a draft or enter a package manually</summary><form id="requestForm"><h3 id="requestEditorTitle">Draft details</h3>
    <div class="request-fields"><label>Why do you need this patch?<textarea name="rationale" maxlength="2000" placeholder="For example: upgrading the framework requires a migration we cannot complete this quarter."></textarea></label><label>Why can’t an existing fix be used? (if applicable)<textarea name="incompatibility" maxlength="2000" placeholder="Describe the compatibility issue or missing coverage."></textarea></label></div>
    <details id="requestAdvanced" ${advancedOpen && scope===previousScope?'open':''}><summary>Package, version and CVEs · advanced</summary><p class="small">Filled automatically when you choose a library. Edit these only to change the request scope.</p><div class="request-fields">
      <label>Current package URL <input name="identity" required placeholder="pkg:maven/org.example/core@1.2.3"></label>
      <label>Scope precision <select name="precision"><option value="exact">Exact version</option><option value="minor">Minor line</option><option value="major">Major line</option></select></label>
      <label>Version or line <input name="line" required placeholder="1.2.3 or 1.2.x"></label>
      <label>CVE / GHSA identifiers <input name="advisories" required placeholder="CVE-2026-12345, GHSA-…"></label>
      <label>Acceptable fixes <select name="remediation"><option value="backpatch">Backpatch</option><option value="backpatch,upstream-fix">Backpatch or upstream fix</option><option value="backpatch,upstream-fix,replacement">Backpatch, upstream fix or replacement</option></select></label>
    </div></details>
    <button id="requestSave" type="submit">Save draft</button> <button id="requestCancel" type="button">Reset form</button></form></details>
    <div class="patch-actions"><button id="previewRequests" ${waiting || !items.length?'disabled':''}>Review draft for download</button><button id="clearRequests">Clear drafts</button></div>
    <p class="small">Exports omit application names, owners, dependency paths and contracts. Review your free-text rationale and exceptions for sensitive information.</p>
    <div id="requestPreview"></div></section>`;
  mount.querySelector('#requestChooseLibrary').onclick=()=>window.dispatchEvent(new CustomEvent('risk-nav:open-libraries'));
  mount.querySelector('#requestBrowsePatches').onclick=()=>window.riskPatches.open();
  mount.querySelector('#requestManual').onclick=()=>{editForm();mount.querySelector('#requestAdvanced').open=true;mount.querySelector('form').elements.identity.focus();};
  mount.querySelectorAll('[data-edit]').forEach(b=>b.onclick=()=>editForm(items[Number(b.dataset.edit)]));
  mount.querySelectorAll('[data-delete]').forEach(b=>b.onclick=()=>{items.splice(Number(b.dataset.delete),1);exported='';render();save();});
  const requestForm=mount.querySelector('form');
  requestForm.oninput=()=>{formDirty=true;mount.querySelector('#requestPreview').textContent='';};
  requestForm.elements.identity.oninput=()=>{if(requestForm.elements.precision.value==='exact')requestForm.elements.line.value=purl(requestForm.elements.identity.value)?.version||'';};
  requestForm.addEventListener('invalid',()=>{mount.querySelector('#requestAdvanced').open=true;},true);
  mount.querySelector('#requestCancel').onclick=()=>editForm();
  mount.querySelector('form').onsubmit=event=>{
    event.preventDefault();const values=Object.fromEntries(new FormData(event.target));
    try {
      const input=validateRequest({...values,advisories:values.advisories.split(/[\s,]+/).filter(Boolean),remediation:values.remediation.split(',')});
      items=addRequest(items.filter(i=>requestKey(i)!==editing),input,activePatches(patchState.feeds));editing=null;formDirty=false;exported='';savedSnapshot=snapshot();render();mount.querySelector('#requestEditor').open=false;save();note('Draft saved locally.');
    } catch(error){note(error.message);}
  };
  mount.querySelector('#clearRequests').onclick=()=>{items=[];editing=null;exported='';render();save();};
  mount.querySelector('#requestWorkFile').onchange=async event=>{
    const file=event.target.files[0];if(!file)return;
    try {if(file.size>10*1024*1024)throw new Error('Work snapshot exceeds 10 MB.');work=normalizeWork(JSON.parse(await file.text()));render(true);save();note('Work references loaded; coverage recalculated.');}
    catch(error){note(error.message);}
  };
  mount.querySelector('#previewRequests').onclick=()=>{
    try {
      if(formDirty)throw new Error('Save your draft changes before reviewing the download.');
      const bundle=exportRequests(items,patchState.dataset,patchState.feeds,work),json=JSON.stringify(bundle,null,2),summary=requestSummary(bundle);
      mount.querySelector('#requestPreview').innerHTML=`<h3>Review your draft</h3><pre class="request-summary">${h(summary)}</pre><div class="patch-actions"><button id="downloadRequestSummary" class="primary">Download request draft</button><button id="downloadRequests">Download JSON</button></div><p>Next: share the downloaded draft through your agreed OSERA request channel. Downloading does not submit it.</p><details><summary>Technical export (JSON)</summary><pre>${h(json)}</pre></details>`;
      const mark=()=>{exported=new Date().toISOString();savedSnapshot=snapshot();save();note('Downloaded locally. Not submitted to OSERA.');};
      mount.querySelector('#downloadRequests').onclick=()=>{download('osera-patch-requests.json',json,'application/json');mark();};
      mount.querySelector('#downloadRequestSummary').onclick=()=>{download('osera-patch-requests.txt',summary,'text/plain');mark();};
    } catch(error){mount.querySelector('#requestPreview').textContent='';note(error.message);}
  };
  editing=null;
  if (draft && scope === previousScope) {
    for (const [key,value] of Object.entries(draft)) mount.querySelector('form').elements[key].value=value;
    editing=editKey;
    mount.querySelector('#requestSave').textContent=editing?'Save changes':'Save draft';
    const item=items.find(i=>requestKey(i)===editing);
    if(item)mount.querySelector('#requestEditorTitle').textContent=`${purl(item.identity).name} · ${item.line}`;
  }
}
const openButton=document.createElement('button');openButton.textContent='Request drafts';openButton.id='openRequestCart';openButton.onclick=openCart;
document.querySelector('#patchCoverage .patch-actions').append(openButton);
window.addEventListener('risk-nav:patch-coverage',()=>render(true));
window.addEventListener('risk-nav:request-patch',event=>addLibrary(event.detail));
window.addEventListener('risk-nav:request-uncovered',()=>{
  loadScope();
  try {
    const drafts=requestsFromAdoption(patchState.dataset);
    for(const draft of drafts)items=addRequest(items,draft,activePatches(patchState.feeds));
    savedSnapshot=snapshot();exported='';render();save();openCart();
    note(`${drafts.length} coverage-gap drafts added. Review current feed evidence before downloading.`);
  } catch(error){openCart();note(error.message);}
});
document.getElementById('detail').addEventListener('click',event=>{
  const button=event.target.closest('[data-request-library]');
  if(!button)return;
  const lib=patchState.dataset?.libraries.find(lib=>lib.id===button.dataset.requestLibrary);
  if(lib)addLibrary(lib);
});
window.riskRequests={open:openCart,setView(mode){mount.hidden=mode!=='patch-requests';},renderMode(){
  render(true);mount.hidden=false;
  document.getElementById('mainTable').hidden=true;document.getElementById('dashboardView').hidden=true;
  document.getElementById('rowCount').textContent=`${items.length} requests`;
  document.getElementById('detail').innerHTML='<h3>Before you request a patch</h3><p><strong>1. Review existing fixes.</strong> A matching published version may already solve the problem, but compatibility still needs assessment.</p><p><strong>2. Explain the gap.</strong> Describe why you need a backpatch or cannot use the existing fix.</p><p><strong>3. Download the draft.</strong> Review the readable summary and share it through your agreed request channel.</p><p class="small">Drafts stay in this browser and are separate for each dataset. Upgrade recipes are a separate tool for applying version changes.</p>';
}};
render();

window.dispatchEvent(new CustomEvent("risk-nav:patch-ready"));
