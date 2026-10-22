import json

import pytest

from extract_org import npm_lock_edges, manifest_paths_from_tree, DepEdge
from refresh_finos import compact_dataset


def lock(packages, version=3):
    return json.dumps({'lockfileVersion': version, 'packages': packages})


def test_runtime_graph_resolves_nested_versions_and_multiple_parents():
    edges = npm_lock_edges(lock({
        '': {'dependencies': {'a': '^1', 'b': '^1'}, 'devDependencies': {'tool': '1'}},
        'node_modules/a': {'version': '1.2.0', 'dependencies': {'shared': '1'}},
        'node_modules/b': {'version': '1.0.0', 'dependencies': {'shared': '2'}, 'peerDependencies': {'peer': '1'}},
        'node_modules/shared': {'version': '1.0.0'},
        'node_modules/b/node_modules/shared': {'version': '2.0.0'},
        'node_modules/peer': {'version': '1.0.0'},
        'node_modules/tool': {'version': '1.0.0', 'dev': True},
    }), 'repo')
    assert len(edges) == 5
    assert {(e.library_id, e.parent_id) for e in edges if not e.direct} == {
        ('npm||shared|1.0.0', 'npm||a|1.2.0'),
        ('npm||shared|2.0.0', 'npm||b|1.0.0'),
        ('npm||peer|1.0.0', 'npm||b|1.0.0'),
    }
    assert all('tool' not in e.library_id for e in edges)


def test_workspaces_aliases_scopes_and_cycles():
    edges = npm_lock_edges(lock({
        '': {'dependencies': {'workspace': '*'}},
        'node_modules/workspace': {'link': True, 'resolved': 'packages/workspace'},
        'packages/workspace': {'name': '@company/workspace', 'version': '1.0.0', 'dependencies': {'alias': 'npm:@scope/real@1'}},
        'node_modules/alias': {'name': '@scope/real', 'version': '1.0.1', 'dependencies': {'workspace': '*'}},
    }, 2), 'repo')
    assert any(e.library_id == 'npm|@scope|real|1.0.1' and e.direct for e in edges)
    assert len(edges) == 3


def test_unknown_lock_format_does_not_silently_remove_manifest_dependencies():
    with pytest.raises(ValueError, match='versions 2 and 3'):
        npm_lock_edges(lock({}, 1), 'repo')


def test_root_manifests_take_priority_over_alphabetical_subdirectories():
    paths = manifest_paths_from_tree([{'type': 'blob', 'path': p} for p in
                                    ['aaa/pom.xml', 'package.json', 'pom.xml', 'tests/package.json']], 2)
    assert paths == ['package.json', 'pom.xml']


def test_compact_inventory_keeps_non_vulnerable_packages_and_all_parent_edges():
    edges = [DepEdge('repo', 'npm||child|1.0.0', 0, 'runtime', parent)
             for parent in ('npm||parent-a|1.0.0', 'npm||parent-b|1.0.0')]
    data = compact_dataset({'libraries': []}, edges)
    inv = data['dependency_inventory']
    assert len(inv['libraries']) == 3
    assert len(inv['edges']) == 2
    assert {inv['libraries'][e[4]] for e in inv['edges']} == {'npm||parent-a|1.0.0', 'npm||parent-b|1.0.0'}


def test_oversized_publish_cannot_replace_existing_snapshot(tmp_path, monkeypatch):
    import refresh_finos as refresh
    monkeypatch.setattr(refresh, 'ROOT', tmp_path)
    monkeypatch.setattr(refresh, 'LOCAL', tmp_path / 'local')
    monkeypatch.setattr(refresh, 'MAX_DATASET_BYTES', 10)
    published = tmp_path / 'data' / 'finos-github-org.json'
    published.parent.mkdir()
    published.write_text('existing')
    with pytest.raises(RuntimeError, match='Refusing to publish'):
        refresh.publish({'libraries': ['a lot of content']}, {})
    assert published.read_text() == 'existing'


def test_finos_distribution_budget():
    from pathlib import Path
    from refresh_finos import MAX_DATASET_BYTES, MAX_REPORT_BYTES
    data = Path(__file__).resolve().parents[1] / 'data'
    assert (data / 'finos-github-org.json').stat().st_size <= MAX_DATASET_BYTES
    report = data / 'finos-coverage.json'
    if report.exists():
        assert report.stat().st_size <= MAX_REPORT_BYTES


def test_shared_version_histories_are_lossless():
    chain = [{'release': '1.0.0', 'max_cvss': 9}, {'release': '1.1.0', 'max_cvss': 0}]
    libraries = [{'namespace': 'npm', 'meta': '', 'proj': 'a', 'version_chain': chain, 'cves': []}
                 for _ in range(2)]
    data = compact_dataset({'libraries': libraries}, [])
    assert data['version_chains'] == {'npm||a': chain}
    for lib in data['libraries']:
        assert data['version_chains'][lib['version_chain_ref']] == chain


def test_scan_pins_content_to_commit_and_uses_workspace_lock_over_ranges(monkeypatch):
    import extract_org as extract
    seen_refs = []
    def get_json(url, *args):
        if '/commits/' in url:
            return {'sha': 'fixed-commit'}
        return {'tree': [{'type': 'blob', 'path': p} for p in
                         ['package-lock.json', 'packages/app/package.json']], 'truncated': False}
    def get_content(owner, repo, path, ref, *args):
        seen_refs.append(ref)
        assert path == 'package-lock.json', 'Workspace range manifest must be superseded by lockfile'
        return lock({'': {}, 'packages/app': {'dependencies': {'a': '^1'}},
                     'node_modules/a': {'version': '1.9.0'}})
    monkeypatch.setattr(extract, 'github_get_json', get_json)
    monkeypatch.setattr(extract, 'github_get_repo_content', get_content)
    edges, report = extract.scan_repo('finos', 'traderX', 'main', 'repo', None, 'https://example.test', 1, 32)
    assert seen_refs == ['fixed-commit']
    assert [e.library_id for e in edges] == ['npm||a|1.9.0']
    assert report['commit'] == 'fixed-commit'
    assert report['status'] == 'extracted'


def test_scan_retains_file_failures_as_partial_coverage(monkeypatch):
    import extract_org as extract
    monkeypatch.setattr(extract, 'github_get_json', lambda url, *a:
                        {'sha': 'commit'} if '/commits/' in url else
                        {'tree': [{'type': 'blob', 'path': 'pom.xml'}], 'truncated': True})
    monkeypatch.setattr(extract, 'github_get_repo_content', lambda *a: '')
    edges, report = extract.scan_repo('finos', 'example', 'main', 'repo', None, 'https://example.test', 1, 1)
    assert edges == []
    assert report['status'] == 'partial'
    assert report['tree_truncated']
    assert report['errors']


def test_osv_range_match_only_adds_versions_to_the_matching_package():
    from resolve_osv_inventory import observed_record
    record = {'id': 'GHSA-example', 'affected': [
        {'package': {'ecosystem': 'npm', 'name': 'a'}, 'ranges': [{'type': 'SEMVER'}]},
        {'package': {'ecosystem': 'npm', 'name': 'b'}, 'versions': ['2.0.0']},
    ]}
    result = observed_record(record, {'npm||a|1.2.3'})
    assert result['affected'][0]['versions'] == ['1.2.3']
    assert result['affected'][1]['versions'] == ['2.0.0']
    assert 'versions' not in record['affected'][0]
    assert observed_record({**record, 'withdrawn': '2026-01-01'}, {'npm||a|1.2.3'}) is None


def test_osv_batch_pagination_preserves_query_identity(monkeypatch):
    import resolve_osv_inventory as osv
    requests = []
    def respond(url, payload):
        requests.append(payload)
        if len(requests) == 1:
            return {'results': [{'vulns': [{'id': 'A'}], 'next_page_token': 'next'}, {'vulns': [{'id': 'B'}]}]}
        assert payload['queries'] == [{'version': '1', 'page_token': 'next'}]
        return {'results': [{'vulns': [{'id': 'C'}]}]}
    monkeypatch.setattr(osv, 'request_json', respond)
    assert osv.query_versions([('one', {'version': '1'}), ('two', {'version': '2'})]) == {
        'A': {'one'}, 'B': {'two'}, 'C': {'one'}}


def test_exact_osv_resolution_replaces_stale_edges_and_materializes_ranges(tmp_path, monkeypatch):
    import sqlite3
    import resolve_osv_inventory as osv
    from ingest_vulns import ensure_schema, ingest_records
    db = tmp_path / 'vulns.db'
    record = {'id': 'GHSA-test', 'aliases': ['CVE-2026-10000'], 'affected': [
        {'package': {'ecosystem': 'npm', 'name': 'a'}, 'versions': ['2.0.0']}]}
    with sqlite3.connect(db) as conn:
        ensure_schema(conn)
        ingest_records(conn, [record])
    record['affected'][0] = {'package': {'ecosystem': 'npm', 'name': 'a'},
                             'ranges': [{'type': 'SEMVER', 'events': [{'introduced': '0'}, {'fixed': '2.0.0'}]}]}
    monkeypatch.setattr(osv, 'query_versions', lambda items: {'GHSA-test': {'npm||a|1.0.0'}})
    monkeypatch.setattr(osv, 'request_json', lambda *a: record)
    osv.resolve_inventory(db, [DepEdge('repo', f'npm||a|{v}', 1, 'runtime') for v in ('1.0.0', '2.0.0')], tmp_path)
    with sqlite3.connect(db) as conn:
        assert conn.execute('SELECT release FROM vuln_version_edges').fetchall() == [('1.0.0',)]
