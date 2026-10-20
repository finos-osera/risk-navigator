import test from 'node:test';
import assert from 'node:assert/strict';
import { addRequest, validateRequest, reviewRequest, exportRequests, impact, normalizeWork, requestFromLibrary } from '../tool/patches/requests.mjs';
import { normalizeFeed } from '../tool/patches/catalog.mjs';
const cve='CVE-2026-12345',second='CVE-2026-12346';
const item={identity:'pkg:maven/org.example/core@1.2.3',precision:'exact',line:'1.2.3',advisories:[cve],remediation:['backpatch']};
const lib={id:'private-path',namespace:'maven',meta:'org.example',proj:'core',release:'1.2.3',consumer_project_ids:['private-app','private-app','other-app'],direct_consumer_project_ids:['private-app'],cves:[{cve_id:cve,kev:true},{cve_id:second}]};
const dataset={meta:{scope_name:'secret-bank'},consumer_projects:[{id:'private-app',owner:'private-owner'},{id:'other-app'}],libraries:[lib]};
const feed=(source_versions=['1.2.3'])=>normalizeFeed({schema_version:1,id:'test',provider:'OSERA',generated_at:'2026-10-20',patches:[{id:'p',target:'pkg:maven/org.example/core@1.2.3-patch',source_versions,advisories:[cve],state:'released'}]});
test('merges repeated compatible requests but keeps different lines separate',()=>{
  let items=addRequest([],item);items=addRequest(items,{...item,advisories:[second]});assert.equal(items.length,1);assert.deepEqual(items[0].advisories,[cve,second]);
  items=addRequest(items,{...item,identity:'pkg:maven/org.example/core@2.1.0',line:'2.1.0'});assert.equal(items.length,2);
});
test('requires exact identity and preserves broad line precision',()=>{
  assert.throws(()=>validateRequest({...item,identity:'pkg:maven/org.example/core'}));
  assert.throws(()=>validateRequest({...item,precision:'minor',line:'2.1.x'}));
  const broad=validateRequest({...item,precision:'major',line:'1.x'});
  assert.equal(reviewRequest(broad,dataset,[feed()]).remaining.length,1);
  const bundle=exportRequests([broad],dataset,[feed()]);assert.deepEqual(bundle.requests[0].scope,{precision:'major',value:'1.x'});
  assert.throws(()=>validateRequest({...item,advisories:['not-an-advisory']}));
});
test('existing fixes block redundant export; residual coverage or explained incompatibility can export',()=>{
  assert.throws(()=>exportRequests([item],dataset,[feed()]),/already has patch coverage/);
  const partial=exportRequests([{...item,advisories:[cve,second]}],dataset,[feed()]);assert.deepEqual(partial.requests[0].advisories,[second]);
  const exception=exportRequests([{...item,incompatibility:'Runtime requirements incompatible'}],dataset,[feed()]);assert.equal(exception.requests.length,1);
});
test('published candidates are visible and never silently suppress a production request',()=>{
  const review=reviewRequest(item,dataset,[feed([])]);assert.equal(review.candidates.length,1);assert.deepEqual(review.remaining,[cve]);
  assert.equal(exportRequests([item],dataset,[feed([])]).requests.length,1);
});
test('shared consumer impacts deduplicate and export contains no private inventory fields',()=>{
  const items=addRequest(addRequest([],item),{...item,advisories:[second]});
  assert.deepEqual(impact(items,dataset,[]),{applications:2,instances:2,direct:1,transitive:1,advisories:2,kev:1});
  const exported=JSON.stringify(exportRequests(items,dataset,[]));
  for(const privateValue of ['private-app','private-owner','secret-bank','private-path','consumer_project_ids'])assert.ok(!exported.includes(privateValue));
});
test('imported OSERA work matches line and advisory scope without becoming a deployed patch',()=>{
  const work=normalizeWork({schema_version:1,requests:[{...item,status:'in_progress',url:'https://github.com/example/backlog/issues/1'}]});
  const review=reviewRequest(item,dataset,[],work);assert.equal(review.work.length,1);assert.equal(review.adopted.length,0);assert.deepEqual(review.remaining,[cve]);
  assert.throws(()=>normalizeWork({schema_version:1,requests:[{...item,status:'in_progress',url:'javascript:alert(1)'}]}));
});
test('refreshing inventory flags manual/stale findings and published coverage is rechecked',()=>{
  assert.equal(reviewRequest(item,{libraries:[]},[]).staleAdvisories.length,1);
  assert.equal(reviewRequest(item,dataset,[]).remaining.length,1);
  assert.equal(reviewRequest(item,dataset,[feed()]).remaining.length,0);
  const request=requestFromLibrary(lib);assert.deepEqual(request.advisories,[cve,second]);
});
