import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { normalizeFeed, analyze, coverage, activePatches, purl, sameArtifact } from '../tool/patches/catalog.mjs';
const target = 'pkg:maven/org.example/core@1.2.3-osera-00001';
const original = 'pkg:maven/org.example/core@1.2.3';
const catalog = (extra = {}) => ({ schema_version: 1, id: 'test', provider: 'Example', generated_at: '2026-10-20T00:00:00Z', patches: [{ id: 'fix', target, source_versions: ['1.2.3'], advisories: ['CVE-1'], aliases: [['CVE-1','GHSA-1']], state: 'released', ...extra }] });
const library = (release, projects, extra = {}) => ({ id: release, namespace:'maven',meta:'org.example',proj:'core',release,consumer_project_ids:projects,cves:[{cve_id:'GHSA-1'}], ...extra });
const estate = { consumer_projects: [{id:'a'},{id:'b'},{id:'c'}], libraries:[library('1.2.3',['a','a','b']),library('1.2.3-osera-00001',['c'])] };
test('deduplicates edges and overlapping feeds, distinguishes available and observed', () => {
  const feeds=[normalizeFeed(catalog()),normalizeFeed({...catalog(),id:'second'})];
  const result=analyze(estate,feeds);
  assert.equal(result.rows.length,3);assert.equal(result.eligible,3);assert.equal(result.observed,1);
  assert.equal(result.availableProjects,2);assert.equal(result.observedProjects,1);assert.equal(result.totalProjects,3);
  assert.deepEqual(result.rows[0].remaining,[]);
});
test('exact target consumption and aliases work without claiming compatibility for older versions', () => {
  const patches=activePatches([normalizeFeed(catalog())]);
  assert.equal(coverage('pkg:maven/org.example/core@1.1.0',['CVE-1'],patches).available.length,0);
  assert.equal(coverage('pkg:maven/org.example/core@1.1.0',['CVE-1'],patches).candidates.length,1);
  assert.equal(coverage(target,['CVE-2'],patches).adopted.length,1);
  assert.deepEqual(coverage(target,['CVE-2'],patches).remaining,['CVE-2']);
  assert.equal(coverage(target+'?classifier=sources',[],patches).adopted.length,0);
});
test('disabled, withdrawn and planned patches cannot credit availability or adoption', () => {
  for(const state of ['withdrawn','planned','superseded']) {
    const result=analyze(estate,[normalizeFeed(catalog({state}))]);assert.equal(result.eligible,0);
  }
  assert.equal(analyze(estate,[{...normalizeFeed(catalog()),enabled:false}]).eligible,0);
});
test('bad input is rejected with visible record errors', () => {
  assert.throws(()=>normalizeFeed({}),/Supported/);
  const feed=normalizeFeed(catalog({target:'bad'}));assert.equal(feed.patches.length,0);assert.equal(feed.errors.length,1);
  assert.equal(purl('pkg:maven/x@%bad'),null);
  assert.equal(sameArtifact(original, target),false);
});
const vex={ '@context':'https://openvex.dev/ns/v0.2.0','@id':'fixture',timestamp:'2026-10-20T00:00:00Z',version:2,statements:[{vulnerability:{name:'CVE-1'},products:[{'@id':target}],status:'fixed'}] };
const sets={feed_version:2,sets:[{set:'example',coordinates:['org.example:core@1.2.3-osera-00001'],state:'in the feed'}]};
test('OSERA release-set evidence is required and mismatched snapshots rejected', () => {
  assert.equal(analyze(estate,[normalizeFeed(vex)]).observed,0);
  assert.equal(analyze(estate,[normalizeFeed(vex,'fixture',sets)]).observed,1);
  assert.throws(()=>normalizeFeed(vex,'fixture',{...sets,feed_version:3}),/different versions/);
  assert.equal(analyze(estate,[normalizeFeed(vex,'fixture',{...sets,sets:[{...sets.sets[0],state:'held'}]})]).observed,0);
});
test('not-affected, affected and under-investigation statements are preserved and never patches', () => {
  for(const status of ['not_affected','affected','under_investigation']) {
    const feed=normalizeFeed({...vex,statements:[{...vex.statements[0],status}]},'fixture',sets);
    assert.equal(feed.patches[0].status,status);assert.equal(analyze(estate,[feed]).eligible,0);
    const conflict=normalizeFeed(vex,'fixture',sets);
    assert.equal(analyze(estate,[feed,conflict]).observed,0);
  }
});
test('zero eligible inventory and project filters keep explicit denominators', () => {
  const empty=analyze({libraries:[],consumer_projects:[]},[]);assert.equal(empty.eligible,0);assert.equal(empty.totalProjects,0);
  const filtered=analyze(estate,[normalizeFeed(catalog())],{project:'a'});assert.equal(filtered.totalProjects,1);assert.equal(filtered.rows.length,1);
});
test('real OSERA-format excerpt retains supplier, aliases and release-set members', () => {
  const bundle=JSON.parse(readFileSync(new URL('./fixtures/osera-feed-excerpt.json',import.meta.url)));
  const feed=normalizeFeed(bundle.openvex,'fixture',bundle.release_sets);
  assert.equal(feed.errors.length,0);assert.equal(feed.patches[0].supplier,'moderne');
  assert.equal(feed.patches[0].state,'released');assert.ok(feed.patches[0].companions.length>1);
});
