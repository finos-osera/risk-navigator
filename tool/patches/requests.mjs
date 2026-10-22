import { purl, libraryPurl, unique, coverage, activePatches, aliasResolver, estateRows } from './catalog.mjs';
const classes = ['backpatch', 'upstream-fix', 'replacement'];
export function validateRequest(input) {
  const identity = purl(input.identity);
  if (!identity) throw new Error('Enter an exact package URL, including its current version.');
  if (!['exact', 'minor', 'major'].includes(input.precision)) throw new Error('Choose exact version, minor line or major line.');
  const line = String(input.line || '').trim();
  if (!line || (input.precision === 'exact' && line !== identity.version) ||
    (input.precision === 'minor' && !/^\d+\.\d+\.x$/.test(line)) ||
    (input.precision === 'major' && !/^\d+\.x$/.test(line))) throw new Error('Line must match the exact version, N.N.x for a minor line, or N.x for a major line.');
  if (input.precision !== 'exact' && !identity.version.startsWith(line.slice(0,-1))) throw new Error('The example version must belong to the requested line.');
  const advisories = unique((input.advisories || []).map(x => String(x).trim()));
  if (!advisories.length || advisories.some(x => !/^(CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})$/i.test(x))) throw new Error('Enter at least one CVE or GHSA identifier.');
  const remediation = unique(input.remediation || ['backpatch']);
  if (!remediation.length || remediation.some(x => !classes.includes(x))) throw new Error('Select a supported remediation class.');
  return { identity: input.identity, package: identity.key, precision: input.precision, line,
    advisories, remediation, rationale: String(input.rationale || '').slice(0,2000),
    incompatibility: String(input.incompatibility || '').slice(0,2000) };
}
export const requestKey = item => `${item.package || purl(item.identity)?.key}|${item.precision}|${item.line}`;
export function addRequest(items, input, patches = []) {
  const item = validateRequest(input), key = requestKey(item), previous = items.find(x => requestKey(x) === key);
  const canonical = aliasResolver(patches);
  const merged = { ...item, advisories: unique([...(previous?.advisories || []), ...item.advisories].map(canonical)),
    remediation: unique([...(previous?.remediation || []), ...item.remediation]),
    rationale: item.rationale || previous?.rationale || '', incompatibility: item.incompatibility || previous?.incompatibility || '' };
  return items.filter(x => requestKey(x) !== key).concat(merged);
}
export function requestFromLibrary(lib) {
  return validateRequest({ identity: libraryPurl(lib), precision: 'exact', line: lib.release,
    advisories: (lib.cves || []).map(c => c.cve_id), remediation:['backpatch'] });
}
export function matchesRequest(item, identity) {
  const parsed = purl(identity);
  return !!parsed && parsed.key === (item.package || purl(item.identity)?.key) && (item.precision === 'exact' ? parsed.version === item.line : parsed.version.startsWith(item.line.slice(0,-1)));
}
export function normalizeWork(doc) {
  if (doc?.schema_version !== 1 || !Array.isArray(doc.requests)) throw new Error('Expected backlog schema_version 1 with requests.');
  return doc.requests.map(record => {
    const item = validateRequest(record);
    if (!['requested','in_progress','covered'].includes(record.status) || !/^https:\/\//.test(record.url || '')) throw new Error('Backlog work requires a status and HTTPS work URL.');
    return { ...item, status: record.status, url: record.url };
  });
}
export function reviewRequest(item, dataset, feeds, work = []) {
  const patches = activePatches(feeds), result = coverage(item.identity,item.advisories,patches);
  const canonical = aliasResolver(patches);
  const related = work.filter(w => requestKey(w) === requestKey(item) && w.advisories.some(a => item.advisories.some(b => canonical(a) === canonical(b))));
  // Evidence about the example artifact never establishes coverage of an entire line.
  const remaining = item.precision === 'exact' ? result.remaining : item.advisories;
  const observations = estateRows(dataset).filter(row => matchesRequest(item,row.identity));
  const staleAdvisories = item.advisories.filter(id => !observations.some(row => row.advisories.some(a => canonical(a) === canonical(id))));
  return { ...result, remaining, work: related, observations, staleAdvisories,
    state: item.precision !== 'exact' ? 'Line scope — review required' : !remaining.length ? 'Existing patch coverage' : result.available.length || result.adopted.length ? 'Partial coverage' : result.candidates.length ? 'Published candidate — review applicability' : related.length ? 'Existing OSERA work' : 'Draft coverage request' };
}
export function impact(items, dataset, feeds) {
  const rows = estateRows(dataset).filter(row => items.some(item => matchesRequest(item,row.identity)));
  const canonical = aliasResolver(activePatches(feeds));
  const findings = rows.flatMap(row => (row.library.cves || []).filter(c => items.some(item => matchesRequest(item,row.identity) && item.advisories.some(a => canonical(a) === canonical(c.cve_id)))));
  return { applications: unique(rows.map(r=>r.project)).length, instances:rows.length,
    direct:unique(rows.filter(r=>r.direct).map(r=>r.project)).length,
    transitive:unique(rows.filter(r=>!r.direct).map(r=>r.project)).length,
    advisories:unique(findings.map(c=>canonical(c.cve_id))).length,
    kev:unique(findings.filter(c=>c.kev).map(c=>canonical(c.cve_id))).length };
}
export function exportRequests(items, dataset, feeds, work = []) {
  if (!items.length) throw new Error('Add at least one request.');
  const requests = [];
  for (const input of items) {
    const item=validateRequest(input), review=reviewRequest(item,dataset,feeds,work);
    if (!review.remaining.length && !item.incompatibility.trim()) throw new Error(`${item.package} already has patch coverage. Remove it or explain why the available fix is incompatible.`);
    requests.push({ package: `pkg:${item.package}`, scope:{precision:item.precision,value:item.line},
      advisories: review.remaining.length ? review.remaining : item.advisories,
      acceptable_remediation: item.remediation,
      ...(item.rationale ? {rationale:item.rationale} : {}),
      ...(item.incompatibility ? {incompatibility:item.incompatibility} : {}) });
  }
  // Explicit allowlist: never serialize local observations, scope names, owners or contracts.
  return {schema_version:1,kind:'osera-coverage-request',requests};
}
export function requestSummary(bundle) {
  return ['OSERA patch coverage request', ...bundle.requests.map(r => `${r.package} — ${r.scope.value} (${r.scope.precision})\nAdvisories: ${r.advisories.join(', ')}\nAcceptable fixes: ${r.acceptable_remediation.join(', ')}${r.rationale ? '\nRationale: '+r.rationale : ''}${r.incompatibility ? '\nExisting fix incompatibility: '+r.incompatibility : ''}`)].join('\n\n');
}
