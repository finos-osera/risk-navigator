// Pure catalog and estate matching functions shared by the coverage view and request cart.
export const unique = values => [...new Set(values.filter(Boolean))].sort();
const strings = value => Array.isArray(value) && value.every(x => typeof x === 'string' && x.trim());
export function purl(value) {
  if (typeof value !== 'string') return null;
  const match = /^pkg:([a-z][a-z0-9.+-]*)\/([^?#]+)@([^@?#]+)(\?[^#]+)?(#.+)?$/.exec(value);
  if (!match) return null;
  try {
    const name = decodeURIComponent(match[2]);
    const version = decodeURIComponent(match[3]);
    return { key: `${match[1]}/${name}`, ecosystem: match[1], name, version, exact: value };
  } catch { return null; }
}
export function libraryPurl(lib) {
  if (purl(lib.purl)) return lib.purl;
  if (!lib.namespace || !lib.proj || !lib.release) return '';
  const name = [lib.meta, lib.proj].filter(Boolean).map(encodeURIComponent).join('/');
  return `pkg:${lib.namespace}/${name}@${encodeURIComponent(lib.release)}`;
}
export function sameArtifact(a, b) {
  const x = purl(a), y = purl(b);
  // Qualifiers/subpaths must not be silently discarded when proving consumption.
  return !!x && !!y && x.key === y.key && x.version === y.version &&
    (a.split('?')[1] || a.split('#')[1] || '') === (b.split('?')[1] || b.split('#')[1] || '');
}
export function normalizeFeed(doc, source = 'Imported feed', releaseSets = null) {
  const errors = [], patches = [];
  if (!doc || typeof doc !== 'object') throw new Error('Feed must be a JSON object.');
  if (doc.schema_version === 1 && Array.isArray(doc.patches)) {
    if (!doc.id || !doc.provider || !doc.generated_at) throw new Error('Catalog requires id, provider and generated_at.');
    for (const [index, item] of doc.patches.entries()) {
      if (!item || !item.id || !purl(item.target) || !strings(item.source_versions) ||
          !strings(item.advisories) || !item.advisories.length ||
          !['released', 'planned', 'withdrawn', 'superseded'].includes(item.state) ||
          (item.source_package && !purl(`${item.source_package}@placeholder`))) {
        errors.push(`Patch ${index + 1}: invalid id, target, source versions, advisories or release state.`); continue;
      }
      patches.push({ ...item, provider: String(doc.provider), source,
        package: item.source_package ? purl(`${item.source_package}@placeholder`).key : purl(item.target).key,
        aliases: Array.isArray(item.aliases) ? item.aliases.filter(x => strings(x) && x.length) : [],
        status: 'fixed', evidence: item.evidence || source });
    }
  } else if (doc['@context'] === 'https://openvex.dev/ns/v0.2.0' && Array.isArray(doc.statements)) {
    if (!doc['@id'] || !doc.timestamp) throw new Error('OpenVEX requires @id and timestamp.');
    if (releaseSets && (!Array.isArray(releaseSets.sets) || releaseSets.feed_version !== doc.version)) {
      throw new Error('OSERA VEX and release sets have different versions; refresh both together.');
    }
    const setsByTarget = new Map();
    for (const set of releaseSets?.sets || []) {
      for (const coord of set.coordinates || []) {
        const match = /^([^:]+):([^@]+)@(.+)$/.exec(coord);
        if (match) setsByTarget.set(`pkg:maven/${match[1]}/${match[2]}@${match[3]}`, set);
      }
    }
    for (const [index, statement] of doc.statements.entries()) {
      const advisory = statement?.vulnerability?.name || statement?.vulnerability?.['@id'];
      if (!advisory || !['fixed', 'affected', 'not_affected', 'under_investigation'].includes(statement.status) ||
          !Array.isArray(statement.products) || !statement.products.length) {
        errors.push(`Statement ${index + 1}: missing vulnerability, products or supported status.`); continue;
      }
      for (const product of statement.products) {
        const target = product?.['@id'], identity = purl(target);
        if (!identity) { errors.push(`Statement ${index + 1}: product is not an exact package URL.`); continue; }
        const set = setsByTarget.get(target);
        patches.push({ id: `${target}:${advisory}`, target, package: identity.key, source_versions: [],
          advisories: [advisory], aliases: [[advisory, ...(statement.vulnerability.aliases || [])]],
          status: statement.status, provider: releaseSets ? 'OSERA' : String(doc.author || 'OpenVEX'),
          supplier: statement.supplier || '', source, evidence: doc['@id'],
          state: releaseSets ? (set?.state === 'in the feed' ? 'released' : 'held') : 'unverified',
          release_set: set?.set || '', companions: set?.coordinates || [] });
      }
    }
  } else throw new Error('Supported formats: patch catalog schema_version 1 or OpenVEX v0.2.0.');
  return { id: String(doc.id || doc['@id']), provider: String(doc.provider || doc.author || 'OpenVEX'),
    version: doc.version ?? doc.feed_version ?? 1, generated_at: doc.generated_at || doc.last_updated || doc.timestamp,
    source, patches, errors, enabled: true, loaded_at: new Date().toISOString() };
}
export function activePatches(feeds) {
  return feeds.filter(feed => feed.enabled).flatMap(feed => feed.patches.map(p => ({ ...p, feed_id: feed.id })));
}
export function aliasResolver(patches) {
  const parent = new Map();
  const root = x => { if (!parent.has(x)) parent.set(x, x); if (parent.get(x) !== x) parent.set(x, root(parent.get(x))); return parent.get(x); };
  for (const patch of patches) for (const group of patch.aliases || []) {
    for (const id of group) parent.set(root(id), root(group[0]));
  }
  return id => root(String(id));
}
export function coverage(identity, advisoryIds, patches) {
  const parsed = purl(identity), canonical = aliasResolver(patches);
  const ids = unique(advisoryIds.map(canonical));
  const relevant = patches.filter(p => p.package === parsed?.key || sameArtifact(p.target, identity));
  const conflicts = patch => relevant.some(other => sameArtifact(other.target, patch.target) &&
    other.advisories.some(a => patch.advisories.some(b => canonical(a) === canonical(b))) &&
    (other.status !== 'fixed' || ['withdrawn', 'held'].includes(other.state)));
  const released = relevant.filter(p => p.status === 'fixed' && p.state === 'released' && !conflicts(p));
  const adopted = released.filter(p => sameArtifact(p.target, identity));
  const options = released.filter(p => p.advisories.some(a => ids.includes(canonical(a))));
  const available = options.filter(p => p.package === parsed?.key && p.source_versions.includes(parsed?.version));
  const covered = unique([...available, ...adopted].flatMap(p => p.advisories.map(canonical)));
  return { adopted, available, candidates: options.filter(p => !available.includes(p) && !adopted.includes(p)),
    other: relevant.filter(p => !released.includes(p)),
    remaining: advisoryIds.filter(id => !covered.includes(canonical(id))),
    covered: advisoryIds.filter(id => covered.includes(canonical(id))) };
}
export function estateRows(dataset) {
  // One component instance is a project + exact package identity, not an edge/path count.
  const instances = new Map();
  for (const lib of dataset.libraries || []) {
    const identity = libraryPurl(lib);
    for (const project of unique(lib.consumer_project_ids || [])) {
      const key = `${project}|${identity || lib.id}`;
      const previous = instances.get(key);
      const advisories = unique([...(previous?.advisories || []), ...(lib.cves || []).map(c => c.cve_id)]);
      instances.set(key, { key, project, identity, library: lib, advisories,
        direct: !!previous?.direct || (lib.direct_consumer_project_ids || []).includes(project) });
    }
  }
  return [...instances.values()];
}
export function analyze(dataset, feeds, filters = {}) {
  const patches = activePatches(feeds).filter(p => !filters.feed || p.feed_id === filters.feed);
  const projects = (dataset.consumer_projects || []).filter(p => !filters.project || p.id === filters.project);
  const matchesByIdentity = new Map();
  const rows = estateRows(dataset).filter(row => !filters.project || row.project === filters.project)
    .filter(row => !filters.search || `${row.identity} ${row.advisories.join(' ')}`.toLowerCase().includes(filters.search.toLowerCase()))
    .map(row => {
      const matchKey = JSON.stringify([row.identity, row.advisories]);
      if (!matchesByIdentity.has(matchKey)) matchesByIdentity.set(matchKey, coverage(row.identity, row.advisories, patches));
      const result = matchesByIdentity.get(matchKey);
      const status = !purl(row.identity) ? 'unknown' : result.adopted.length ? 'observed' : result.available.length ? 'available' : result.candidates.length ? 'candidate' : result.other.length ? 'unconfirmed' : 'gap';
      return { ...row, ...result, status };
    });
  const eligible = rows.filter(r => r.available.length || r.adopted.length);
  return { rows: rows.filter(r => !filters.status || r.status === filters.status),
    totalProjects: unique([...projects.map(p => p.id), ...rows.map(r => r.project)]).length,
    availableProjects: unique(rows.filter(r => r.available.length).map(r => r.project)).length,
    observedProjects: unique(rows.filter(r => r.adopted.length).map(r => r.project)).length,
    eligible: eligible.length, observed: eligible.filter(r => r.adopted.length).length,
    candidates: rows.filter(r => r.candidates.length).length,
    unknown: rows.filter(r => ['unknown', 'unconfirmed'].includes(r.status)).length };
}
