import { activePatches, analyze, purl, unique, sameArtifact } from './catalog.mjs';

// Distance describes version shape, never proof of compatibility.
export function distance(source, target) {
  const a = purl(source), b = purl(target);
  if (!a || !b || a.key !== b.key) return 'Needs assessment';
  if (sameArtifact(source, target)) return 'Already observed';
  const x = /^(\d+)\.(\d+)(?:\.(\d+))?/.exec(a.version), y = /^(\d+)\.(\d+)(?:\.(\d+))?/.exec(b.version);
  if (x && !x[3]) x[3] = "0";
  if (y && !y[3]) y[3] = "0";
  if (!x || !y) return 'Needs assessment';
  if (+y[1] < +x[1] || (+y[1] === +x[1] && (+y[2] < +x[2] || (+y[2] === +x[2] && +y[3] < +x[3])))) return 'Older version line · needs assessment';
  if (x[1] !== y[1]) return 'Major migration';
  if (x[2] !== y[2]) return 'Minor upgrade';
  return /osera/i.test(b.version) ? 'Same-line OSERA backpatch' : 'Same-line patch update';
}
export function inventory(dataset, feeds) {
  const analysis = analyze(dataset, feeds), groups = new Map();
  for (const patch of activePatches(feeds)) {
    if (patch.status !== 'fixed' || patch.state !== 'released') continue;
    const id = patch.target;
    if (!groups.has(id)) groups.set(id, { id, target: id, records: [], adopted: [], available: [], candidates: [], blocked: [] });
    groups.get(id).records.push(patch);
  }
  for (const row of analysis.rows) for (const field of ['adopted', 'available', 'candidates', 'other']) {
    for (const target of unique(row[field].map(p => p.target))) {
      const group = groups.get(target);
      if (group) group[field === 'other' ? 'blocked' : field].push(row);
    }
  }
  return [...groups.values()].map(group => {
    group.available = group.available.filter(row => !group.adopted.includes(row));
    const observations = [...new Map([...group.adopted, ...group.available, ...group.candidates, ...group.blocked].map(row => [row.key, row])).values()];
    return { ...group, observations,
      providers: unique(group.records.map(p => p.provider)),
      advisories: unique(group.records.flatMap(p => p.advisories)),
      companions: unique(group.records.flatMap(p => p.companions || [])),
      versions: unique(observations.map(row => purl(row.identity)?.version)),
      efforts: unique(observations.map(row => distance(row.identity, group.target))),
      projects: unique(observations.map(row => row.project)),
    };
  }).sort((a,b) => b.available.length - a.available.length || b.candidates.length - a.candidates.length || Number(b.efforts.some(e=>e.startsWith('Same-line'))) - Number(a.efforts.some(e=>e.startsWith('Same-line'))) || b.target.localeCompare(a.target,undefined,{numeric:true}));
}
