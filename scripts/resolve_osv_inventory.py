"""Resolve OSV range-only advisories for observed package versions via querybatch."""
from __future__ import annotations

import copy
import json
import re
import sqlite3
import time
import urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

from common import parse_library_id, split_coords
from extract_org import now_iso
from ingest_vulns import ingest_records

API = 'https://api.osv.dev/v1'
ECOSYSTEMS = {'npm': 'npm', 'maven': 'Maven', 'pypi': 'PyPI'}


def request_json(url, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json', 'User-Agent': 'risk-navigator/0.1'})
            with urllib.request.urlopen(req, timeout=60) as response:
                return json.load(response)
        except Exception:
            if attempt == 2:
                raise
            time.sleep(attempt + 1)


def query_versions(items):
    findings = defaultdict(set)
    pending = items
    while pending:
        results = request_json(f'{API}/querybatch', {'queries': [q for _, q in pending]})['results']
        if len(results) != len(pending):
            raise ValueError('Incomplete OSV batch response')
        following = []
        for (lid, query), result in zip(pending, results):
            for vuln in result.get('vulns', []):
                findings[vuln['id']].add(lid)
            if result.get('next_page_token'):
                following.append((lid, {**query, 'page_token': result['next_page_token']}))
        pending = following
    return findings


def observed_record(record, identities):
    """Add only API-confirmed observed versions to their matching affected package."""
    if record.get('withdrawn'):
        return None
    result = copy.deepcopy(record)
    for affected in result.get('affected', []):
        package = affected.get('package', {})
        coords = split_coords(package.get('ecosystem', ''), package.get('name', ''))
        observed = [release for ns, meta, proj, release in map(parse_library_id, identities) if (ns, meta, proj) == coords]
        affected['versions'] = sorted(set(affected.get('versions', [])) | set(observed))
    return result


def resolve_inventory(db, edges, local):
    items = []
    for lid in sorted({e.library_id for e in edges}):
        ns, meta, proj, version = parse_library_id(lid)
        if ns not in ECOSYSTEMS or not re.fullmatch(r'[0-9][0-9A-Za-z_.+!-]*', version):
            continue
        name = f'{meta}:{proj}' if ns == 'maven' else (f'{meta}/{proj}' if meta else proj)
        items.append((lid, {'package': {'ecosystem': ECOSYSTEMS[ns], 'name': name}, 'version': version}))
    print(f'Checking {len(items)} observed package versions against OSV ranges', flush=True)
    matched = defaultdict(set)
    with ThreadPoolExecutor(max_workers=4) as pool:
        for batch in pool.map(query_versions, [items[i:i+100] for i in range(0, len(items), 100)]):
            for osv_id, lids in batch.items():
                matched[osv_id].update(lids)
    ids = sorted(matched)
    with ThreadPoolExecutor(max_workers=8) as pool:
        records = list(pool.map(lambda rid: request_json(f'{API}/vulns/{quote(rid, safe="")}'), ids))
    adjusted = [observed_record(record, matched[record['id']]) for record in records]
    adjusted = [record for record in adjusted if record is not None]
    # All network work must succeed before updating the local DB.
    conn = sqlite3.connect(db)
    try:
        for lid, _ in items:
            conn.execute('DELETE FROM vuln_version_edges WHERE namespace=? AND meta=? AND proj=? AND release=?', parse_library_id(lid))
        ingest_records(conn, adjusted, progress_every=0)
    finally:
        conn.close()
    stats = {'queried_at': now_iso(), 'queried_package_versions': len(items), 'matched_advisories': len(ids),
             'method': 'OSV querybatch exact-version matching, including range-only records',
             'limitations': 'The viewer is CVE-based; advisories without a CVE alias are not shown as CVE findings.'}
    (local / 'osv-exact-versions.json').write_text(json.dumps({'stats': stats, 'matches': {k: sorted(v) for k,v in matched.items()}}))
    return stats
