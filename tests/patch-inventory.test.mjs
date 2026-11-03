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
