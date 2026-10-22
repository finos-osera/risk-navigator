import { patchState, escapeHtml as h } from './panel.mjs';
import { activePatches } from './catalog.mjs';
import { addRequest, requestFromLibrary, requestKey, validateRequest, normalizeWork, reviewRequest, impact, exportRequests, requestSummary } from './requests.mjs';
const mount = document.getElementById('patchRequestMount');
document.querySelector('.table-wrap').append(mount);
mount.hidden=true;
let scope = '', items = [], work = [], savedSnapshot = '', exported = '', editing = null;
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
  scope=next; items=[];work=[];savedSnapshot='';exported='';editing=null;
  try {
    const saved=JSON.parse(localStorage.getItem(storageKey())||'{}');
    items=(saved.items||[]).reduce((acc,item)=>addRequest(acc,validateRequest(item)),[]);
    work=normalizeWork({schema_version:1,requests:saved.work||[]});
    savedSnapshot=String(saved.savedSnapshot||'');exported=String(saved.exported||'');
  } catch { items=[];work=[]; }
}
function openCart() {
  window.dispatchEvent(new CustomEvent('risk-nav:open-requests'));
  const details=mount.querySelector('details');if(details)details.open=true;
}
function addLibrary(lib) {
  try {
    items=addRequest(items,requestFromLibrary(lib),activePatches(patchState.feeds));
    savedSnapshot=snapshot();exported='';render();save();openCart();note('Added to the local request cart. Review existing coverage before exporting.');
  } catch(error) { openCart();note(error.message); }
}
function editForm(item=null) {
  const form=mount.querySelector('form'); form.reset();
  editing=item?requestKey(item):null;
  if(item)for(const field of ['identity','precision','line','rationale','incompatibility'])form.elements[field].value=item[field]||'';
  if(item){form.elements.advisories.value=item.advisories.join(', ');form.elements.remediation.value=item.remediation.join(',');}
  mount.querySelector('#requestSave').textContent=item?'Save changes':'Add request';
  form.elements.identity.focus();
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
  const wasOpen=mount.querySelector('details')?.open||false;
  const count=impact(items,patchState.dataset,patchState.feeds);
  mount.innerHTML=`<details ${wasOpen?'open':''}><summary>OSERA patch request cart (${items.length})</summary>
    <p>Requests are scoped to this dataset and are independent of library display filters. Collect missing patch coverage, check existing fixes, then review a local export. Export does not submit a request or mark a patch deployed.</p>
    <p class="small">Scope: ${h(scope)} · ${items.length} requests · ${count.applications} unique applications · ${count.instances} observed component instances · ${count.direct} direct / ${count.transitive} transitive applications (may overlap) · ${count.advisories} observed advisories · ${count.kev} KEVs. Potential impact only; partial inventories undercount.</p>
    ${savedSnapshot && savedSnapshot!==snapshot()?'<p class="patch-warning">Feed or inventory evidence changed since the cart was saved. Coverage below has been recalculated; review before export.</p>':''}
    <p class="small">${work.length} imported work references. ${work.length?'Imported work may be stale; verify its linked status.':'No backlog snapshot loaded: existing requests are unknown.'} ${exported?'Last local export: '+h(exported)+'. No submission acknowledgment.':''}</p>
    <label>Import OSERA work references <input id="requestWorkFile" type="file" accept=".json,application/json"></label>
    <div id="requestMessage" role="status" aria-live="polite"></div>
    <div class="request-list">${items.map((item,index)=>{
      const r=reviewRequest(item,patchState.dataset,patchState.feeds,work);
      return `<article class="patch-source"><strong>${h(item.package)} · ${h(item.line)} (${h(item.precision)})</strong><p>${h(r.state)} · remaining: ${h(r.remaining.join(', ')||'none of the requested advisories')}</p>
      <p class="small">Requested: ${h(item.advisories.join(', '))}. ${r.available.length} applicable records · ${r.adopted.length} exact-artifact matches · ${r.candidates.length} published candidate records. ${r.staleAdvisories.length?'Not present in current observed findings: '+h(r.staleAdvisories.join(', '))+'. Check manual/stale requests.':''}</p>
      ${r.candidates.length?'<p class="patch-warning">A published fix may already address this need. Review its applicability before requesting production.</p>':''}
      <details><summary>Existing patch / work evidence</summary><p class="small">Only visible source details are shown; enabled hidden sources still contribute to coverage checks.</p><pre>${h(JSON.stringify([...r.available,...r.adopted,...r.candidates].filter(p=>patchState.feeds.some(f=>f.id===p.feed_id&&f.visible)).map(p=>({target:p.target,provider:p.provider,advisories:p.advisories,evidence:p.evidence,release_set:p.release_set})),null,2))}</pre>${r.work.map(w=>`<p><a href="${h(w.url)}" target="_blank" rel="noreferrer">${h(w.status)}: ${h(w.line)}</a> · ${h(w.advisories.join(', '))}</p>`).join('')||'<p>No matching imported work reference.</p>'}</details>
      ${item.incompatibility?`<p>Existing-fix exception: ${h(item.incompatibility)}</p>`:''}
      <button data-edit="${index}">Edit</button> <button data-delete="${index}">Remove</button></article>`;
    }).join('')||'<p>No requests yet. Add one from an estate row or enter one below.</p>'}</div>
    <form id="requestForm"><h3>Manual request / edit</h3><div class="patch-actions">
      <label>Current package URL <input name="identity" required placeholder="pkg:maven/org.example/core@1.2.3"></label>
      <label>Scope precision <select name="precision"><option value="exact">Exact version</option><option value="minor">Minor line</option><option value="major">Major line</option></select></label>
      <label>Version or line <input name="line" required placeholder="1.2.3 or 1.2.x"></label>
      <label>CVE / GHSA identifiers <input name="advisories" required placeholder="CVE-2026-12345, GHSA-…"></label>
      <label>Acceptable fixes <select name="remediation"><option value="backpatch">Backpatch</option><option value="backpatch,upstream-fix">Backpatch or upstream fix</option><option value="backpatch,upstream-fix,replacement">Backpatch, upstream fix or replacement</option></select></label>
    </div><div class="patch-actions"><label>Rationale (included in export)<textarea name="rationale" maxlength="2000"></textarea></label><label>Existing fix incompatibility (included in export)<textarea name="incompatibility" maxlength="2000"></textarea></label></div>
    <button id="requestSave" type="submit">Add request</button> <button id="requestCancel" type="button">Reset form</button></form>
    <div class="patch-actions"><button id="previewRequests">Review export</button><button id="clearRequests">Clear cart</button></div>
    <p class="small">Exports omit application names, owners, dependency paths and contracts. Review your free-text rationale and exceptions for sensitive information.</p>
    <div id="requestPreview"></div></details>`;
  mount.querySelectorAll('[data-edit]').forEach(b=>b.onclick=()=>editForm(items[Number(b.dataset.edit)]));
  mount.querySelectorAll('[data-delete]').forEach(b=>b.onclick=()=>{items.splice(Number(b.dataset.delete),1);exported='';render();save();});
  mount.querySelector('#requestCancel').onclick=()=>editForm();
  mount.querySelector('form').onsubmit=event=>{
    event.preventDefault();const values=Object.fromEntries(new FormData(event.target));
    try {
      const input=validateRequest({...values,advisories:values.advisories.split(/[\s,]+/).filter(Boolean),remediation:values.remediation.split(',')});
      items=addRequest(items.filter(i=>requestKey(i)!==editing),input,activePatches(patchState.feeds));editing=null;exported='';savedSnapshot=snapshot();render();save();note('Request saved locally.');
    } catch(error){note(error.message);}
  };
  mount.querySelector('#clearRequests').onclick=()=>{items=[];editing=null;exported='';render();save();};
  mount.querySelector('#requestWorkFile').onchange=async event=>{
    const file=event.target.files[0];if(!file)return;
    try {if(file.size>10*1024*1024)throw new Error('Work snapshot exceeds 10 MB.');work=normalizeWork(JSON.parse(await file.text()));render();save();note('Work references loaded; coverage recalculated.');}
    catch(error){note(error.message);}
  };
  mount.querySelector('#previewRequests').onclick=()=>{
    try {
      const bundle=exportRequests(items,patchState.dataset,patchState.feeds,work),json=JSON.stringify(bundle,null,2),summary=requestSummary(bundle);
      mount.querySelector('#requestPreview').innerHTML=`<h3>Review exactly what will be exported</h3><pre>${h(json)}</pre><details><summary>Human-readable summary</summary><pre>${h(summary)}</pre></details><button id="downloadRequests">Download JSON</button> <button id="downloadRequestSummary">Download summary</button><p class="small">Downloading does not submit to OSERA.</p>`;
      const mark=()=>{exported=new Date().toISOString();savedSnapshot=snapshot();save();note('Downloaded locally. Not submitted to OSERA.');};
      mount.querySelector('#downloadRequests').onclick=()=>{download('osera-patch-requests.json',json,'application/json');mark();};
      mount.querySelector('#downloadRequestSummary').onclick=()=>{download('osera-patch-requests.txt',summary,'text/plain');mark();};
    } catch(error){mount.querySelector('#requestPreview').textContent='';note(error.message);}
  };
  editing=null;
  if (draft && scope === previousScope) {
    for (const [key,value] of Object.entries(draft)) mount.querySelector('form').elements[key].value=value;
    editing=editKey;
    mount.querySelector('#requestSave').textContent=editing?'Save changes':'Add request';
  }
}
const openButton=document.createElement('button');openButton.textContent='OSERA request cart';openButton.id='openRequestCart';openButton.onclick=openCart;
document.querySelector('#patchCoverage .patch-actions').append(openButton);
window.addEventListener('risk-nav:patch-coverage',()=>render(true));
window.addEventListener('risk-nav:request-patch',event=>addLibrary(event.detail));
window.riskRequests={open:openCart,setView(mode){mount.hidden=mode!=='patch-requests';},renderMode(){
  render(true);mount.hidden=false;const details=mount.querySelector('details');if(details)details.open=true;
  document.getElementById('mainTable').hidden=true;document.getElementById('dashboardView').hidden=true;
  document.getElementById('rowCount').textContent=`${items.length} requests`;
  document.getElementById('detail').innerHTML='<h3>OSERA patch requests</h3><p>Add missing coverage from Libraries or Patch coverage, or enter it manually here.</p><p>Enabled sources, including hidden ones, are checked before export. Manage sources in Patch coverage.</p><p>Review the JSON before downloading. Downloads stay local and do not submit to OSERA.</p>';
}};
render();

window.dispatchEvent(new CustomEvent("risk-nav:patch-ready"));
