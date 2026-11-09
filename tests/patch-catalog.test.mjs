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
test('hidden sources still count, disabled sources do not, and independent inventories retain provenance', () => {
  const one={...normalizeFeed(catalog()),visible:false};
  const two={...normalizeFeed({...catalog(),id:'supplemental'}),enabled:false,visible:true};
  const result=analyze(estate,[one,two]);assert.equal(result.eligible,3);
  assert.deepEqual(activePatches([one,two]).map(p=>p.feed_id),['test']);
  one.enabled=false;assert.equal(analyze(estate,[one,two]).eligible,0);
  two.enabled=true;assert.deepEqual(activePatches([one,two]).map(p=>p.feed_id),['supplemental']);
});

test('imports the provider catalog contract from main without losing provenance or digest conflicts', () => {
  const bundle=JSON.parse(readFileSync(new URL('../data/fixtures/patch-feeds-estate-sample.json',import.meta.url)));
  const feed=normalizeFeed(bundle.feeds[1]);
  assert.equal(feed.errors.length,0);
  assert.equal(feed.id,bundle.feeds[1].config.feed_id);
  const patch=feed.patches[0];
  assert.equal(patch.provider,'OSERA');
  assert.ok(patch.artifact_digest);
  assert.ok(patch.evidence.length);
  const conflict={...feed,id:'conflicting',patches:[{...patch,artifact_digest:'sha256:different'}]};
  const lib={namespace:'maven',meta:'at.yawk.lz4',proj:'lz4-java',release:'1.8.1.1-osera-00001',consumer_project_ids:['a'],cves:[]};
  assert.equal(analyze({libraries:[lib]},[feed,conflict]).observed,0);
});

import { parseCatalogCsv, comparePatchOptions, ingestOseraBacklogSnapshot, reconcileBacklogWithEstate } from '../tool/patches/catalog.mjs';

test('compares upstream, OSERA and commercial options through common catalog and blocks unready options (#23)', () => {
  const catalogDoc = JSON.parse(readFileSync(new URL('../data/fixtures/patch-catalog-backlog/common-catalog-upstream-osera-commercial.json', import.meta.url), 'utf8'));
  const overlayDoc = JSON.parse(readFileSync(new URL('../data/fixtures/patch-catalog-backlog/member-catalog-overlay.json', import.meta.url), 'utf8'));
  const csvText = readFileSync(new URL('../data/fixtures/patch-catalog-backlog/common-catalog-commercial.csv', import.meta.url), 'utf8');
  const parsedCsv = parseCatalogCsv(csvText, { feed_id: 'csv-feed' });
  assert.equal(parsedCsv.patches.length, 2);

  const cmp = comparePatchOptions(
    { purl: 'pkg:maven/org.springframework/spring-web@5.3.20', advisories: ['GHSA-22243-spring', 'CVE-2024-22259', 'CVE-2024-22262'] },
    [catalogDoc],
    overlayDoc,
    '2026-10-28T00:00:00Z'
  );
  assert.deepEqual(cmp.providers_represented, ['commercial', 'osera', 'upstream']);
  assert.equal(cmp.ready_options.length, 3);
  const byId = Object.fromEntries(cmp.options.map(o => [o.patch_id, o]));
  assert.equal(byId['osera-coverage-commitment-without-release'].ready, false);
  assert.equal(byId['osera-future-delayed-availability'].ready, false);
  assert.equal(byId['commercial-expired-entitlement-herodevs'].ready, false);
  assert.equal(byId['osera-withdrawn-artifact-00001'].ready, false);
  assert.equal(byId['commercial-unentitled-fork-vendor'].ready, false);
  assert.equal(byId['commercial-missing-vendor-mapping'].ready, false);
});

test('ingests OSERA backlog snapshot and keeps deployed Tomcat distinct from latest-patch graph (#24)', () => {
  const rawSnapshot = JSON.parse(readFileSync(new URL('../data/fixtures/patch-catalog-backlog/osera-backlog-tomcat-snapshot.json', import.meta.url), 'utf8'));
  const ingested = ingestOseraBacklogSnapshot(rawSnapshot);
  assert.equal(ingested.metadata.snapshot_consistent, true);
  const tomcatLine = ingested.supported_lines.find(l => l.line_id === 'tomcat-embed-core:9.0.x');
  assert.equal(tomcatLine.coverage_state, 'partial_coverage');
  assert.equal(tomcatLine.unique_vulnerability_fix_count, 1);
  assert.equal(tomcatLine.companion_artifact_count, 4);

  const reconciled = reconcileBacklogWithEstate(ingested, [
    { application_id: 'app-1', purl: 'pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@9.0.50', advisories: ['CVE-2024-24549', 'CVE-2023-46589'] }
  ]);
  assert.equal(reconciled.rows[0].deployed_version, '9.0.50');
  assert.equal(reconciled.rows[0].pinned_baseline, '9.0.70');
  assert.equal(reconciled.rows[0].latest_patch_resolution, '9.0.85-osera-00001');
  assert.equal(reconciled.rows[0].deployed_findings_cleared_by_reference_graph, false);
  assert.deepEqual(reconciled.rows[0].active_deployed_findings, ['CVE-2024-24549', 'CVE-2023-46589']);
});

test('omitted evaluationTime defaults to current UTC timestamp for entitlement and support expiry (#23)', () => {
  const catalogDoc = {
    schema_version: 'osera-patch-catalog/v1',
    feed_id: 'default-eval-time',
    provider: 'HeroDevs',
    provider_kind: 'commercial',
    patches: [
      {
        patch_id: 'expired-past',
        provider: 'HeroDevs',
        provider_kind: 'commercial',
        replacement_purl: 'pkg:maven/org.springframework/spring-web@5.3.39-herodevs-1',
        applicable_versions: ['5.3.20'],
        fixed_advisories: ['CVE-2024-22259'],
        release_state: 'released',
        evidence_links: [{ kind: 'attestation', url: 'https://example.test/ev1' }],
        vendor_version_mapping: { vendor_backport_base: '5.3.20', upstream_equivalent_version: '5.3.34', fix_evidence: 'https://example.test/ev1' },
      },
      {
        patch_id: 'active-future',
        provider: 'HeroDevs',
        provider_kind: 'commercial',
        replacement_purl: 'pkg:maven/org.springframework/spring-web@5.3.39-herodevs-2',
        applicable_versions: ['5.3.20'],
        fixed_advisories: ['CVE-2024-22259'],
        release_state: 'released',
        evidence_links: [{ kind: 'attestation', url: 'https://example.test/ev2' }],
        vendor_version_mapping: { vendor_backport_base: '5.3.20', upstream_equivalent_version: '5.3.34', fix_evidence: 'https://example.test/ev2' },
      },
    ],
  };
  const overlayDoc = {
    entitlements: [
      { patch_id: 'expired-past', provider: 'HeroDevs', status: 'entitled', expires_at: '2020-01-01T00:00:00Z' },
      { patch_id: 'active-future', provider: 'HeroDevs', status: 'entitled', expires_at: '2099-01-01T00:00:00Z' },
    ],
    approvals: { HeroDevs: 'approved' },
  };
  const cmp = comparePatchOptions(
    { purl: 'pkg:maven/org.springframework/spring-web@5.3.20', advisories: ['CVE-2024-22259'] },
    [catalogDoc],
    overlayDoc
  );
  const byId = Object.fromEntries(cmp.options.map(o => [o.patch_id, o]));
  assert.equal(byId['expired-past'].ready, false);
  assert.ok(byId['expired-past'].blocked_reasons.includes('expired_entitlement'));
  assert.equal(byId['active-future'].ready, true);
});

test('reconcileBacklogWithEstate matches fixes strictly to deployed maintenance line and is order-independent (#24)', () => {
  const rawSnapshot = JSON.parse(readFileSync(new URL('../data/fixtures/patch-catalog-backlog/osera-backlog-tomcat-snapshot.json', import.meta.url), 'utf8'));

  const unsupported = reconcileBacklogWithEstate(rawSnapshot, [
    { application_id: 'app-10', purl: 'pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@10.1.0', advisories: ['CVE-2024-24549'] }
  ]);
  const row10 = unsupported.rows[0];
  assert.equal(row10.deployed_maintenance_line, '10.1.x');
  assert.equal(row10.matched_line_id, null);
  assert.equal(row10.coverage_status, 'unsupported_maintenance_line');
  assert.equal(row10.pinned_baseline, null);
  assert.equal(row10.latest_patch_resolution, null);
  assert.equal(row10.consume_coordinate, null);
  assert.equal(row10.consumption_bom, null);
  assert.deepEqual(row10.available_fixes, []);
  assert.equal(row10.member_deployment_state, 'deployed_vulnerable_unsupported_line');
  assert.equal(row10.cross_line_migration_options.length, 1);
  assert.equal(row10.cross_line_migration_options[0].maintenance_line, '9.0.x');

  const multiLineRaw = structuredClone(rawSnapshot);
  multiLineRaw.supported_lines_csv += 'maven,org.apache.tomcat.embed,tomcat-embed-core,tomcat-embed-core:10.1.x,10.1.x,10.1.18,10.1.20-osera-00001,org.apache.tomcat.embed:tomcat-embed-core:10.1.20-osera-00001,org.apache.tomcat:tomcat-bom:10.1.20-osera-00001,active\n';
  multiLineRaw.backlog_items.push({
    item_id: 'tomcat-10-cve-2024-24549',
    line_id: 'tomcat-embed-core:10.1.x',
    library: 'org.apache.tomcat.embed:tomcat-embed-core',
    maintenance_line: '10.1.x',
    advisory_id: 'CVE-2024-24549',
    status: 'fixed',
    fixed_by: 'pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@10.1.20-osera-00001',
    consume_coordinate: 'pkg:maven/org.apache.tomcat/tomcat-bom@10.1.20-osera-00001?type=pom',
  });
  const multiLineSnapshot = ingestOseraBacklogSnapshot(multiLineRaw);
  const observations = [
    { application_id: 'app-9', purl: 'pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@9.0.50', advisories: ['CVE-2024-24549'] },
    { application_id: 'app-10', purl: 'pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@10.1.10', advisories: ['CVE-2024-24549'] },
  ];
  const forward = reconcileBacklogWithEstate(multiLineSnapshot, observations);
  const reversedSnapshot = structuredClone(multiLineSnapshot);
  reversedSnapshot.supported_lines.reverse();
  reversedSnapshot.backlog_items.reverse();
  const backward = reconcileBacklogWithEstate(reversedSnapshot, observations);

  assert.deepEqual(forward.rows, backward.rows);
  const byApp = Object.fromEntries(forward.rows.map(r => [r.application_id, r]));
  assert.equal(byApp['app-9'].pinned_baseline, '9.0.70');
  assert.deepEqual(byApp['app-9'].available_fixes.map(f => f.fixed_by), ['pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@9.0.85-osera-00001']);
  assert.equal(byApp['app-10'].pinned_baseline, '10.1.18');
  assert.deepEqual(byApp['app-10'].available_fixes.map(f => f.fixed_by), ['pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@10.1.20-osera-00001']);
});
