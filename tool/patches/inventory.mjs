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

// Numeric release prefixes are an explicit UI selection policy, not applicability evidence.
export function releaseParts(version) {
  const match = /^(\d+(?:\.\d+)+)(?:-osera-(\d+))?$/.exec(version);
  return match ? { numbers: match[1].split('.').map(Number), revision: Number(match[2] || 0) } : null;
}
export function compareReleases(a, b) {
  const x = releaseParts(a), y = releaseParts(b);
  if (!x || !y) return 0;
  for (let i=0;i<Math.max(x.numbers.length,y.numbers.length);i++) {
    const difference=(x.numbers[i]||0)-(y.numbers[i]||0);
    if(difference)return difference;
  }
  return x.revision-y.revision;
}
export function releaseTier(source, target) {
  const a=purl(source), b=purl(target);
  if(!a || !b || a.key!==b.key)return null;
  const x=releaseParts(a.version), y=releaseParts(b.version);
  if(!x || !y || compareReleases(b.version,a.version)<0 || x.numbers[0]!==y.numbers[0])return null;
  if(x.numbers[1]!==y.numbers[1])return 2;
  // A two-part source such as 1.33 defines the whole 1.33 line.
  if(x.numbers.every((n,i)=>n===y.numbers[i]))return 0;
  return 1;
}
export function selectInventory(rows, policy='baseline') {
  const maximum={baseline:0,patch:1,minor:2}[policy] ?? 0;
  const selected=new Map();
  const observations=new Map(rows.flatMap(r=>r.observations.map(o=>[o.key,o])));
  for(const observation of observations.values()) {
    const options=rows.filter(r=>[...r.available,...r.candidates].some(o=>o.key===observation.key));
    // Prefer the least invasive tier; fall back only when that tier has no target.
    for(const provider of unique(options.flatMap(r=>r.providers))) {
      const allowed=options.filter(r=>r.providers.includes(provider)).map(r=>({row:r,tier:releaseTier(observation.identity,r.target)})).filter(x=>x.tier!==null && x.tier<=maximum);
      allowed.sort((a,b)=>a.tier-b.tier || compareReleases(purl(b.row.target).version,purl(a.row.target).version));
      if(allowed.length) {
        const target=allowed[0].row.target;
        if(!selected.has(target))selected.set(target,new Set());
        selected.get(target).add(observation.key);
      }
    }
  }
  return rows.map(row=>{
    const keys=selected.get(row.target)||new Set();
    const available=row.available.filter(o=>keys.has(o.key));
    const candidates=row.candidates.filter(o=>keys.has(o.key));
    // Actual adoption remains historical evidence, never an upgrade suggestion.
    const observations=[...new Map([...row.adopted,...available,...candidates].map(o=>[o.key,o])).values()];
    return {...row,available,candidates,blocked:[],observations,
      versions:unique(observations.map(o=>purl(o.identity)?.version)),
      efforts:unique(observations.map(o=>distance(o.identity,row.target))),
      projects:unique(observations.map(o=>o.project))};
  }).filter(row=>row.observations.length);
}
export function latestCatalog(rows) {
  const groups=new Map();
  for(const row of rows) {
    const identity=purl(row.target), version=releaseParts(identity?.version||'');
    if(!version)continue;
    for(const provider of row.providers) {
      const key=`${identity.key}|${provider}|${version.numbers.slice(0,2).join('.')}`;
      const previous=groups.get(key);
      if(!previous || compareReleases(identity.version,purl(previous.target).version)>0)groups.set(key,row);
    }
  }
  return [...new Map([...groups.values()].map(row=>[row.target,row])).values()];
}
