import test from 'node:test';
import assert from 'node:assert/strict';
import { inventory, distance } from '../tool/patches/inventory.mjs';
import { normalizeFeed } from '../tool/patches/catalog.mjs';
const target='pkg:maven/org.example/core@1.2.3-osera-1';
const feed=normalizeFeed({schema_version:1,id:'test',provider:'OSERA',generated_at:'2026-11-02',patches:[{id:'fix',target,source_versions:['1.2.3'],advisories:['CVE-1'],state:'released'}]});
const lib=(id,version,projects)=>({id,purl:`pkg:maven/org.example/core@${version}`,consumer_project_ids:projects,cves:[{cve_id:'CVE-1'},{cve_id:'CVE-2'}]});
test('target inventory preserves partial adoption and deduplicates observations across feeds',()=>{
 const [row]=inventory({libraries:[lib('old','1.2.3',['a','a']),lib('new','1.2.3-osera-1',['b'])]},[feed,{...feed,id:'second'}]);
 assert.equal(row.adopted.length,1);assert.equal(row.available.length,1);assert.equal(row.projects.length,2);assert.deepEqual(row.advisories,['CVE-1']);
});
test('same-line candidate stays unconfirmed and outside-estate targets remain browsable',()=>{
 const uncertain={...feed,patches:feed.patches.map(p=>({...p,source_versions:[]}))};
 const [row]=inventory({libraries:[lib('old','1.2.3',['a'])]},[uncertain]);
 assert.equal(row.available.length,0);assert.equal(row.candidates.length,1);
 assert.equal(inventory({libraries:[]},[feed]).length,1);
});
test('distance labels do not imply upgrade suitability and flag older versions',()=>{
 assert.equal(distance('pkg:maven/org.example/core@1.2',target),'Same-line OSERA backpatch');
 assert.equal(distance('pkg:maven/org.example/core@1.2.3',target),'Same-line OSERA backpatch');
 assert.equal(distance('pkg:maven/org.example/core@2.0.0',target),'Older version line · needs assessment');
 assert.equal(distance('pkg:maven/org.example/core@1.1.0',target),'Minor upgrade');
 assert.equal(distance('pkg:maven/org.example/core@0.2.0',target),'Major migration');
});

import { selectInventory, releaseTier, compareReleases, latestCatalog } from '../tool/patches/inventory.mjs';
function choices(source, versions) {
 const observation={key:'app|'+source,identity:'pkg:maven/org.example/core@'+source,project:'app'};
 return versions.map(version=>({target:'pkg:maven/org.example/core@'+version,providers:['OSERA'],adopted:[],available:[],candidates:[observation],blocked:[],observations:[observation]}));
}
test('two-part baseline selects only latest same-minor release, never older lines',()=>{
 const rows=choices('1.33',['1.26.1-osera-99999','1.33.1-osera-00001','1.33.1-osera-00009','1.33.1-osera-00010','1.34.1-osera-00001']);
 assert.deepEqual(selectInventory(rows).map(r=>r.target.split('@')[1]),['1.33.1-osera-00010']);
 assert.deepEqual(selectInventory(rows,'minor').map(r=>r.target.split('@')[1]),['1.33.1-osera-00010']);
});
test('exact baseline first, later patches and minors are opt-in fallbacks',()=>{
 const versions=['1.2.4.1-osera-5555','1.2.10-osera-9999','1.3.0-osera-1','2.0.0-osera-1'];
 assert.equal(selectInventory(choices('1.2.4',versions),'minor')[0].target.split('@')[1],versions[0]);
 assert.equal(selectInventory(choices('1.2.4',versions.slice(1))).length,0);
 assert.equal(selectInventory(choices('1.2.4',versions.slice(1)),'patch')[0].target.split('@')[1],versions[1]);
 assert.equal(selectInventory(choices('1.2.4',versions.slice(2)),'patch').length,0);
 assert.equal(selectInventory(choices('1.2.4',versions.slice(2)),'minor')[0].target.split('@')[1],versions[2]);
 assert.equal(selectInventory(choices('1.2.4',['1.2.3-osera-99999','2.0.0-osera-1']),'minor').length,0);
});
test('OSERA revision and extra numeric segments are compared numerically',()=>{
 assert.ok(compareReleases('1.2.4.10-osera-9','1.2.4.2-osera-100')>0);
 assert.equal(releaseTier('pkg:maven/org.example/core@1.2.4-osera-10','pkg:maven/org.example/core@1.2.4-osera-9'),null);
 assert.equal(releaseTier('pkg:maven/org.example/core@1.2.4','pkg:maven/org.example/core@1.20.4-osera-1'),2);
 assert.equal(latestCatalog(choices('1.33',['1.33.1-osera-1','1.33.1-osera-10'])).length,1);
});

import { marketplace } from '../tool/patches/inventory.mjs';
test('marketplace presence does not require CVE overlap or upgrade eligibility',()=>{
 const rows=choices('1.33',['1.26.1-osera-1','1.33.1-osera-1','1.33.1-osera-2']);
 const catalog=marketplace(rows,{libraries:[{purl:'pkg:maven/org.example/core@1.33',cves:[]}]});
 assert.equal(catalog.length,2);
 assert.ok(catalog.every(r=>r.estateMatches.length===1));
 assert.equal(catalog.find(r=>r.line==='1.26').sameLineVersions.length,0);
 assert.deepEqual(catalog.find(r=>r.line==='1.33').sameLineVersions,['1.33']);
 assert.equal(catalog.find(r=>r.line==='1.33').target.split('@')[1],'1.33.1-osera-2');
 const outside=marketplace(rows,{libraries:[]});assert.ok(outside.every(r=>!r.estateMatches.length));
});
test('marketplace exact patch use requires exact artifact identity',()=>{
 const rows=choices('1.33',['1.33.1-osera-2']);
 assert.equal(marketplace(rows,{libraries:[{purl:rows[0].target} ]})[0].exactUse,true);
 assert.equal(marketplace(rows,{libraries:[{purl:rows[0].target+'?classifier=sources'} ]})[0].exactUse,false);
});

test('compact inventory includes non-vulnerable observations and respects project scope', () => {
  const target='pkg:maven/org.example/core@1.2.3-osera-00001';
  const dataset={libraries:[],consumer_projects:[{id:'app'}],dependency_inventory:{schema_version:1,
    libraries:['maven|org.example|core|1.2.3-osera-00001'],projects:['app','outside'],
    edge_columns:['project','library','direct','qualifier','parent'],edges:[[0,0,1,'runtime',null],[0,0,1,'runtime',null],[1,0,0,'runtime',null]]}};
  const feed=normalizeFeed({schema_version:1,id:'compact',provider:'Member',generated_at:'2026-11-04',patches:[{id:'fix',target,source_versions:[],advisories:['CVE-2026-12345'],state:'released'}]});
  const rows=inventory(dataset,[feed]);
  assert.equal(rows[0].adopted.length,1);
  assert.deepEqual(rows[0].projects,['app']);
  const catalog=marketplace(rows,dataset);
  assert.equal(catalog[0].exactUse,true);
  assert.deepEqual(catalog[0].estateMatches[0].lib.consumer_project_ids,['app']);
  assert.equal(marketplace(rows,{...dataset,consumer_projects:[]})[0].estateMatches.length,0);
  assert.equal(inventory({...dataset,inventory_scope:{transitiveOnly:true}},[feed])[0].adopted.length,0);
});
