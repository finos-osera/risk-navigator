import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {
  canonicalLibraryId,
  canonicalPackageId,
  formatPurl,
  isVersionRangeOrUnresolved,
  makeLibraryId,
  makePackageId,
  parseLibraryId,
  parsePackageId,
  parsePurlSpec,
  sameArtifactPurl,
  samePackagePurl
} from '../tool/purl-identity.mjs';
import { analyze, estateRows, inventoryLibraries, libraryPurl, purl, sameArtifact } from '../tool/patches/catalog.mjs';

test('PURL parser and formatter round-trip Maven, scoped npm, PyPI, and RPM identities', () => {
  const maven = makeLibraryId('maven', 'org.springframework', 'spring-web', '5.3.39');
  assert.equal(maven, 'pkg:maven/org.springframework/spring-web@5.3.39');
  assert.equal(makePackageId('maven', 'org.springframework', 'spring-web'), 'pkg:maven/org.springframework/spring-web');
  assert.deepEqual(parseLibraryId(maven), {
    namespace: 'maven',
    meta: 'org.springframework',
    proj: 'spring-web',
    release: '5.3.39'
  });

  const scopedNpm = makeLibraryId('npm', '@finos', 'perspective', '2.10.0');
  assert.equal(scopedNpm, 'pkg:npm/%40finos/perspective@2.10.0');
  assert.deepEqual(parseLibraryId(scopedNpm), {
    namespace: 'npm',
    meta: '@finos',
    proj: 'perspective',
    release: '2.10.0'
  });

  const pypi = canonicalLibraryId('pypi||Friendly_BARD|v1.2.0');
  assert.equal(pypi, 'pkg:pypi/friendly-bard@1.2.0');
  assert.equal(canonicalPackageId('pypi||Friendly_BARD'), 'pkg:pypi/friendly-bard');

  const rpm = makeLibraryId('rpm', 'rhel', 'xz', '5.4.5-1');
  assert.equal(rpm, 'pkg:rpm/rhel/xz@5.4.5-1');
  assert.deepEqual(parsePackageId('pkg:rpm/rhel/xz'), {
    namespace: 'rpm',
    meta: 'rhel',
    proj: 'xz'
  });
});

test('Legacy pipe IDs and canonical PURLs work seamlessly in inventoryLibraries and estateRows', () => {
  const dataset = {
    consumer_projects: [{ id: 'github|finos|demo-app' }],
    libraries: [
      {
        id: 'pkg:maven/org.springframework/spring-web@5.3.39',
        namespace: 'maven',
        meta: 'org.springframework',
        proj: 'spring-web',
        release: '5.3.39',
        cves: [{ cve_id: 'CVE-2024-38816' }],
        consumer_project_ids: ['github|finos|demo-app'],
        direct_consumer_project_ids: ['github|finos|demo-app']
      }
    ],
    dependency_inventory: {
      schema_version: 1,
      libraries: [
        'pkg:maven/org.springframework/spring-web@5.3.39',
        'pkg:npm/%40finos/perspective@2.10.0',
        'npm||legacy-pipe-lib|1.0.0'
      ],
      projects: ['github|finos|demo-app'],
      edge_columns: ['project', 'library', 'direct', 'qualifier', 'parent'],
      edges: [
        [0, 0, 1, 'runtime', null],
        [0, 1, 1, 'runtime', null],
        [0, 2, 0, 'runtime', 1]
      ]
    }
  };

  const expanded = inventoryLibraries(dataset);
  assert.equal(expanded.length, 3);
  const rows = estateRows(dataset);
  const identities = rows.map(r => r.identity).sort();
  assert.deepEqual(identities, [
    'pkg:maven/org.springframework/spring-web@5.3.39',
    'pkg:npm/%40finos/perspective@2.10.0',
    'pkg:npm/legacy-pipe-lib@1.0.0'
  ]);
});

test('Rejects non-package project/scope identities and unresolved version ranges', () => {
  assert.deepEqual(parseLibraryId('github|finos|legend-studio'), {
    namespace: '',
    meta: '',
    proj: '',
    release: ''
  });
  assert.equal(canonicalLibraryId('github|finos|legend-studio'), '');
  assert.equal(purl('github|finos|legend-studio'), null);
  assert.equal(isVersionRangeOrUnresolved('^1.2.0'), true);
  assert.equal(isVersionRangeOrUnresolved('${project.version}'), true);
  assert.equal(isVersionRangeOrUnresolved('5.3.39'), false);
  assert.equal(
    sameArtifact(
      'pkg:npm/%40scope/pkg@1.0.0?arch=x64&os=linux#lib/index.js',
      'pkg:npm/%40scope/pkg@1.0.0?os=linux&arch=x64#lib/index.js'
    ),
    true
  );
  assert.equal(
    samePackagePurl('pkg:npm/%40scope/pkg@1.0.0', 'pkg:npm/%40scope/pkg@2.0.0'),
    true
  );
});
