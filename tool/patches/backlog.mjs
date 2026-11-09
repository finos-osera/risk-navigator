// Provider-neutral patch catalog option comparison (#23) and read-only OSERA backlog / consumption BOM adapter (#24).
import { purl, unique } from './catalog.mjs';

const splitList = value => Array.isArray(value)
  ? value.map(x => String(x || '').trim()).filter(Boolean)
  : typeof value === 'string' && value.trim()
    ? value.split(/[;|,]/).map(x => x.trim()).filter(Boolean)
    : [];

const deriveMinorLine = version => {
  const clean = String(version || '').split('-osera-')[0];
  const m = /^(\d+)\.(\d+)/.exec(clean);
  return m ? `${m[1]}.${m[2]}.x` : (clean || 'unknown');
};

const parseCsvRows = text => {
  const lines = String(text || '').trim().split(/\r?\n/).filter(Boolean);
  if (lines.length < 2) return [];
  const parseLine = line => {
    const out = [];
    let cur = '', inQuotes = false;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (ch === '"') {
        if (inQuotes && line[i + 1] === '"') { cur += '"'; i++; }
        else inQuotes = !inQuotes;
      } else if (ch === ',' && !inQuotes) {
        out.push(cur.trim()); cur = '';
      } else cur += ch;
    }
    out.push(cur.trim());
    return out;
  };
  const headers = parseLine(lines[0]);
  return lines.slice(1).map(line => {
    const cols = parseLine(line);
    return Object.fromEntries(headers.map((h, idx) => [h, cols[idx] ?? '']));
  });
};

export function parseCatalogCsv(csvText, config = {}) {
  const rows = parseCsvRows(csvText);
  const patches = rows.map((row, idx) => {
    const vendorMapping = (row.upstream_equivalent_version || row.vendor_backport_base)
      ? {
          vendor_backport_base: row.vendor_backport_base || '',
          upstream_equivalent_version: row.upstream_equivalent_version || '',
          fix_evidence: row.fix_evidence || row.evidence_url || '',
        }
      : null;
    return {
      patch_id: row.patch_id || `csv-patch-${idx + 1}`,
      provider: row.provider || config.provider || 'CatalogCSV',
      provider_kind: (row.provider_kind || config.provider_kind || 'commercial').toLowerCase(),
      supplier: row.supplier || row.provider || config.provider || 'CatalogCSV',
      original_purl: row.original_purl || null,
      replacement_purl: row.replacement_purl || '',
      applicable_versions: splitList(row.applicable_versions),
      maintenance_line: row.maintenance_line || null,
      fixed_advisories: splitList(row.fixed_advisories),
      aliases: splitList(row.aliases),
      residual_advisories: splitList(row.residual_advisories),
      runtime_constraints: {
        ...(row.java_min ? { java_min: row.java_min } : {}),
        ...(row.abi_compatible ? { abi_compatible: ['true', '1', 'yes'].includes(row.abi_compatible.toLowerCase()) } : {}),
      },
      required_companions: splitList(row.required_companions),
      release_state: (row.release_state || 'released').toLowerCase(),
      available_from: row.available_from || null,
      published_at: row.published_at || config.as_of || '2026-10-25T00:00:00Z',
      artifact_digest: row.artifact_digest || null,
      evidence_links: splitList(row.evidence_links || row.evidence_url).map(url => ({ kind: 'advisory_or_attestation', url })),
      support_dates: {
        ...(row.support_start ? { support_start: row.support_start } : {}),
        ...((row.support_end || row.eol_at) ? { support_end: row.support_end || row.eol_at } : {}),
      },
      vendor_version_mapping: vendorMapping,
      withdrawn: ['true', '1', 'yes'].includes(String(row.withdrawn || '').toLowerCase()),
      superseded_by: row.superseded_by || null,
    };
  });
  return {
    schema_version: 'osera-patch-catalog/v1',
    feed_id: config.feed_id || 'csv-catalog',
    provider: config.provider || 'CatalogCSV',
    provider_kind: config.provider_kind || 'commercial',
    as_of: config.as_of || '2026-10-25T00:00:00Z',
    patches,
  };
}

export function normalizeCommonCatalogEntry(raw, feedMeta = {}, memberOverlay = null, evaluationTime = null) {
  const evalTs = evaluationTime || new Date().toISOString();
  const replacementPurl = String(raw.replacement_purl || raw.target || '').trim();
  const parsedRep = purl(replacementPurl);
  const oseraMatch = parsedRep ? /^(.+)-osera-(\d+)$/i.exec(parsedRep.version) : null;
  const provider = String(raw.provider || feedMeta.provider || (oseraMatch ? 'OSERA' : 'Upstream')).trim();
  const providerKind = String(raw.provider_kind || feedMeta.provider_kind || (oseraMatch ? 'osera' : 'upstream')).trim().toLowerCase();

  let releaseState = String(raw.release_state || raw.state || 'released').trim().toLowerCase();
  const withdrawn = Boolean(raw.withdrawn) || releaseState === 'withdrawn';
  if (withdrawn) releaseState = 'withdrawn';
  const supersededBy = raw.superseded_by ? String(raw.superseded_by).trim() : null;
  if (supersededBy && releaseState === 'released') releaseState = 'superseded';

  const applicableVersions = splitList(raw.applicable_versions || raw.source_versions);
  if (oseraMatch && !applicableVersions.includes(oseraMatch[1])) applicableVersions.push(oseraMatch[1]);

  const fixedAdvisories = splitList(raw.fixed_advisories || raw.advisories);
  const aliases = splitList(raw.aliases);
  const residualAdvisories = splitList(raw.residual_advisories);
  const requiredCompanions = splitList(raw.required_companions || raw.companions);
  const availableFrom = raw.available_from || null;
  const publishedAt = raw.published_at || feedMeta.last_refresh || feedMeta.as_of || '';
  const supportDates = raw.support_dates || {};
  const supportEnd = supportDates.support_end || supportDates.eol_at || raw.support_end || null;
  const vendorMapping = raw.vendor_version_mapping || null;
  const evidenceLinks = Array.isArray(raw.evidence_links) ? raw.evidence_links : [];

  const patchId = String(raw.patch_id || raw.id || `${provider}:${replacementPurl}`);
  const libraryCoord = parsedRep ? parsedRep.name.replace('/', ':') : '';

  // Never infer entitlement, price, or commercial coverage from marketing or the existence of a fork (#23).
  let entitlementStatus = ['upstream', 'osera'].includes(providerKind) ? 'not_required' : 'unentitled';
  let entitlementExpiresAt = null;
  let approvalStatus = providerKind === 'upstream' ? 'approved' : 'pending';
  let internalRepositoryUrl = null;
  let pricing = null;

  if (memberOverlay && typeof memberOverlay === 'object') {
    const matchedEnt = (memberOverlay.entitlements || []).find(ent =>
      ent.patch_id
        ? ent.patch_id === patchId
        : (ent.provider && ent.provider.toLowerCase() === provider.toLowerCase() && ['*', libraryCoord].includes(ent.library || ent.package || '*'))
    );
    if (matchedEnt) {
      entitlementExpiresAt = matchedEnt.expires_at || null;
      const rawStatus = String(matchedEnt.status || 'entitled').toLowerCase();
      if (entitlementExpiresAt && entitlementExpiresAt < evalTs) entitlementStatus = 'expired';
      else if (['entitled', 'active'].includes(rawStatus)) entitlementStatus = 'entitled';
      else if (rawStatus === 'expired') entitlementStatus = 'expired';
      else entitlementStatus = 'unentitled';
      if (matchedEnt.approval_status) approvalStatus = String(matchedEnt.approval_status).toLowerCase();
      if (matchedEnt.internal_repository_url) internalRepositoryUrl = matchedEnt.internal_repository_url;
      if (matchedEnt.pricing) pricing = matchedEnt.pricing;
    }
    if (memberOverlay.approvals?.[patchId]) approvalStatus = String(memberOverlay.approvals[patchId]).toLowerCase();
    else if (memberOverlay.approvals?.[provider] && approvalStatus === 'pending') approvalStatus = String(memberOverlay.approvals[provider]).toLowerCase();
    if (!internalRepositoryUrl && memberOverlay.repository_routing?.[provider]) internalRepositoryUrl = memberOverlay.repository_routing[provider];
  }

  const blockedReasons = [];
  if (!parsedRep) blockedReasons.push('invalid_replacement_purl');
  if (withdrawn || releaseState === 'withdrawn') blockedReasons.push('withdrawn_artifact');
  if (releaseState === 'superseded') blockedReasons.push('superseded_artifact');
  if (['coverage_commitment', 'supported_line', 'backlog_closed', 'planned', 'draft', 'candidate'].includes(releaseState)) {
    blockedReasons.push('coverage_commitment_without_release');
  }
  if (releaseState === 'future_availability' || (availableFrom && availableFrom > evalTs)) {
    blockedReasons.push('future_delayed_availability');
  }
  if (supportEnd && supportEnd < evalTs) blockedReasons.push('support_window_expired');
  if (providerKind === 'commercial') {
    if (entitlementStatus === 'expired') blockedReasons.push('expired_entitlement');
    else if (entitlementStatus !== 'entitled') blockedReasons.push('missing_commercial_entitlement');
    const hasMapping = Boolean(vendorMapping && (vendorMapping.vendor_backport_base || vendorMapping.upstream_equivalent_version));
    const hasEvidence = Boolean(evidenceLinks.length || vendorMapping?.fix_evidence);
    if (!hasMapping || !hasEvidence) blockedReasons.push('missing_commercial_vendor_mapping_or_fix_evidence');
  } else if (entitlementStatus === 'expired') {
    blockedReasons.push('expired_entitlement');
  }
  if (['rejected', 'blocked'].includes(approvalStatus)) blockedReasons.push('member_policy_rejected');
  if (!fixedAdvisories.length) blockedReasons.push('no_fixed_advisories_declared');

  const ready = blockedReasons.length === 0 && releaseState === 'released';
  return {
    patch_id: patchId,
    provider,
    provider_kind: providerKind,
    library: libraryCoord,
    replacement_purl: replacementPurl,
    replacement_version: parsedRep?.version || '',
    applicable_versions: applicableVersions,
    maintenance_line: raw.maintenance_line || deriveMinorLine(parsedRep?.version),
    fixed_advisories: fixedAdvisories,
    aliases,
    residual_advisories: residualAdvisories,
    runtime_constraints: raw.runtime_constraints || {},
    required_companions: requiredCompanions,
    release_state: releaseState,
    available_from: availableFrom,
    published_at: publishedAt,
    evidence_freshness: publishedAt || 'unknown',
    artifact_digest: raw.artifact_digest || null,
    evidence_links: evidenceLinks,
    support_dates: { support_start: supportDates.support_start || null, support_end: supportEnd },
    vendor_version_mapping: vendorMapping,
    withdrawn,
    superseded_by: supersededBy,
    entitlement_status: entitlementStatus,
    entitlement_expires_at: entitlementExpiresAt,
    approval_status: approvalStatus,
    internal_repository_url: internalRepositoryUrl,
    pricing,
    ready,
    blocked_reasons: blockedReasons,
  };
}

export function comparePatchOptions(component, catalogSources, memberOverlay = null, evaluationTime = null) {
  const evalTs = evaluationTime || new Date().toISOString();
  const compPurl = purl(component.purl || '');
  const sourceVersion = compPurl?.version || component.version || '';
  const libraryCoord = compPurl ? compPurl.name.replace('/', ':') : (component.library || '');
  const observedAdvisories = splitList(component.advisories || component.cves);

  const normalizedAll = [];
  for (const src of catalogSources || []) {
    const doc = src.document || src;
    const cfg = src.config || src;
    if (cfg.enabled === false || doc.enabled === false) continue;
    const meta = {
      feed_id: cfg.feed_id || doc.feed_id || doc.id || 'catalog',
      provider: cfg.provider || doc.provider,
      provider_kind: cfg.provider_kind || doc.provider_kind,
      as_of: cfg.last_refresh || doc.as_of || doc.generated_at || doc.timestamp,
    };
    for (const p of doc.patches || []) {
      normalizedAll.push(normalizeCommonCatalogEntry(p, meta, memberOverlay, evalTs));
    }
  }

  // Canonical advisory alias union (prefer CVE-* over GHSA-*)
  const aliasMap = new Map();
  for (const opt of normalizedAll) {
    if (opt.fixed_advisories.length === 1) {
      const root = opt.fixed_advisories[0];
      for (const al of opt.aliases) aliasMap.set(al, root);
    }
  }
  const canonicalAdv = id => aliasMap.get(id) || id;
  const observedCanonical = observedAdvisories.map(canonicalAdv);

  const seen = new Set();
  const options = [];
  for (const opt of normalizedAll) {
    if (opt.library !== libraryCoord) continue;
    const key = `${opt.provider}|${opt.replacement_purl}|${opt.patch_id}`;
    if (seen.has(key)) continue;
    seen.add(key);

    const copy = { ...opt, blocked_reasons: [...opt.blocked_reasons], source_version: sourceVersion, exact_target: opt.replacement_purl };
    const applicable = copy.applicable_versions.includes(sourceVersion) ||
      (copy.provider_kind === 'commercial' && copy.vendor_version_mapping?.vendor_backport_base === sourceVersion);
    if (!applicable && !copy.blocked_reasons.includes('source_version_not_in_applicable_versions')) {
      copy.blocked_reasons.push('source_version_not_in_applicable_versions');
      copy.ready = false;
    }

    const fixedCanon = new Set([...copy.fixed_advisories, ...copy.aliases].map(canonicalAdv));
    copy.addressed_vulnerabilities = observedAdvisories.filter((_, i) => fixedCanon.has(observedCanonical[i]));
    const remObserved = observedAdvisories.filter((_, i) => !fixedCanon.has(observedCanonical[i]));
    const explicitResiduals = copy.residual_advisories.filter(r => !remObserved.map(canonicalAdv).includes(canonicalAdv(r)));
    copy.remaining_vulnerabilities = [...remObserved, ...explicitResiduals];
    copy.eligibility_state = copy.ready ? 'ready' : (copy.blocked_reasons.length ? 'blocked' : 'review_required');
    options.push(copy);
  }

  const rank = { osera: 0, upstream: 1, commercial: 2, member: 3 };
  options.sort((a, b) => (a.ready === b.ready ? 0 : a.ready ? -1 : 1) ||
    (a.remaining_vulnerabilities.length - b.remaining_vulnerabilities.length) ||
    ((rank[a.provider_kind] ?? 9) - (rank[b.provider_kind] ?? 9)));

  return {
    schema_version: 'osera-patch-catalog/v1',
    evaluated_at: evalTs,
    component: { library: libraryCoord, source_version: sourceVersion, observed_advisories: observedAdvisories },
    options,
    ready_options: options.filter(o => o.ready),
    blocked_options: options.filter(o => !o.ready),
    providers_represented: unique(options.map(o => o.provider_kind)),
  };
}

export function ingestOseraBacklogSnapshot(snapshot) {
  const meta = snapshot.metadata || snapshot;
  const sourceCommit = String(meta.source_commit || '').trim();
  const commitTimestamp = String(meta.commit_timestamp || meta.timestamp || '').trim();
  const dataQualityIssues = [];
  if (!sourceCommit) dataQualityIssues.push({ kind: 'missing_source_commit', severity: 'error' });

  for (const [artifact, sha] of Object.entries(meta.component_commits || {})) {
    if (sourceCommit && sha && sha !== sourceCommit) {
      dataQualityIssues.push({ kind: 'inconsistent_snapshot', severity: 'error', artifact, expected_commit: sourceCommit, observed_commit: sha });
    }
  }

  const rawLines = Array.isArray(snapshot.supported_lines)
    ? snapshot.supported_lines
    : parseCsvRows(snapshot.supported_lines_csv || '');
  const linesById = new Map();
  const supportedLines = rawLines.map((row, idx) => {
    const library = row.library || row.coordinate || `${row.group_id}:${row.artifact_id}`;
    const lineId = row.line_id || `${library}:${deriveMinorLine(row.pinned_baseline || row.latest_patch)}`;
    const consume = String(row.consume_coordinate ?? row.consume ?? '').trim();
    const status = String(row.line_status || row.status || 'active').toLowerCase();
    if (!consume && ['active', 'released', 'supported'].includes(status)) {
      dataQualityIssues.push({ kind: 'empty_consume_coordinate', severity: 'warning', line_id: lineId, library });
    }
    const ln = {
      row_index: idx,
      line_id: lineId,
      ecosystem_type: (row.ecosystem || 'maven').toLowerCase(),
      library,
      maintenance_line: row.maintenance_line || deriveMinorLine(row.pinned_baseline || row.latest_patch),
      pinned_baseline: row.pinned_baseline || '',
      latest_patch: row.latest_patch || '',
      consume_coordinate: consume,
      line_status: status,
    };
    linesById.set(lineId, ln);
    return ln;
  });

  const excludedKeys = new Set();
  const exclusions = (snapshot.exclusions || []).map(exc => {
    const lib = exc.library || exc.coordinate || '';
    const adv = exc.advisory_id || exc.cve_id || '*';
    excludedKeys.add(`${lib}|${adv}`);
    return { library: lib, advisory_id: adv, status: 'excluded', counts_as_remediation: false, reason: exc.reason || '' };
  });

  const bomsByLine = new Map();
  const consumptionBoms = (snapshot.consumption_boms || []).map(bom => {
    const members = (bom.members || bom.artifacts || []).map(m => ({
      purl: m.purl || m.coordinate,
      role: m.role || 'companion',
      counts_as_separate_vulnerability_fix: m.role === 'primary',
    }));
    const rec = {
      line_id: bom.line_id,
      bom_purl: bom.bom_coordinate || bom.purl,
      released_with: splitList(bom.released_with),
      members,
      primary_fix_artifacts: members.filter(m => m.counts_as_separate_vulnerability_fix).map(m => m.purl),
      companion_artifacts: members.filter(m => !m.counts_as_separate_vulnerability_fix).map(m => m.purl),
    };
    if (bom.line_id) bomsByLine.set(bom.line_id, rec);
    return rec;
  });

  for (const ua of snapshot.unexpected_artifacts || []) {
    const art = typeof ua === 'string' ? ua : (ua.purl || ua.coordinate);
    dataQualityIssues.push({ kind: 'unexpected_artifact_version', severity: 'warning', artifact: art });
  }

  const advAliases = new Map();
  for (const item of snapshot.backlog_items || []) {
    const adv = item.advisory_id || item.cve_id || '';
    const aliases = splitList(item.aliases);
    const allIds = [adv, ...aliases].filter(Boolean);
    const cveRoot = allIds.find(x => x.toUpperCase().startsWith('CVE-')) || allIds[0];
    if (cveRoot) for (const id of allIds) advAliases.set(id, cveRoot);
  }
  const canonicalAdv = id => advAliases.get(id) || id;

  const seenItems = new Set();
  const backlogItems = [];
  for (const item of snapshot.backlog_items || []) {
    const lib = item.library || item.coordinate || '';
    const lineId = item.line_id || '';
    const rawAdv = item.advisory_id || item.cve_id || '';
    const adv = canonicalAdv(rawAdv);
    const dedup = `${lib}|${lineId}|${adv}`;
    if (seenItems.has(dedup)) continue;
    seenItems.add(dedup);

    let status = String(item.status || 'open').toLowerCase().replace('-', '_');
    if (excludedKeys.has(`${lib}|${adv}`) || excludedKeys.has(`${lib}|*`)) status = 'excluded';
    const fixedBy = String(item.fixed_by || '').trim() || null;
    const lineInfo = linesById.get(lineId);
    const consumeCoord = String(item.consume_coordinate ?? lineInfo?.consume_coordinate ?? '').trim() || null;

    let availabilityGranted = false;
    let qualityState = 'valid';
    if (status === 'fixed') {
      if (!fixedBy) {
        qualityState = 'missing_fixed_by_evidence';
        dataQualityIssues.push({ kind: 'missing_fixed_by_on_fixed_item', severity: 'error', library: lib, advisory_id: adv });
      } else if (!consumeCoord) {
        qualityState = 'empty_consume_coordinate';
        dataQualityIssues.push({ kind: 'fixed_item_empty_consume_coordinate', severity: 'warning', library: lib, advisory_id: adv });
      } else {
        availabilityGranted = true;
      }
    }
    const fixedByPurl = fixedBy ? purl(fixedBy) : null;
    backlogItems.push({
      line_id: lineId || lineInfo?.line_id || `${lib}:default`,
      library: lib,
      maintenance_line: item.maintenance_line || lineInfo?.maintenance_line || (fixedByPurl?.version ? deriveMinorLine(fixedByPurl.version) : ''),
      advisory_id: adv,
      aliases: splitList(item.aliases),
      status,
      fixed_by: fixedBy,
      fixed_by_version: fixedByPurl?.version || null,
      consume_coordinate: consumeCoord,
      availability_granted: availabilityGranted,
      data_quality_state: qualityState,
    });
  }

  const lineSummaries = supportedLines.map(ln => {
    const items = backlogItems.filter(i => i.line_id === ln.line_id);
    const avail = items.filter(i => i.availability_granted);
    const unresolved = items.filter(i => !i.availability_granted && i.status !== 'excluded');
    const bom = bomsByLine.get(ln.line_id) || null;
    return {
      ...ln,
      coverage_state: avail.length && unresolved.length ? 'partial_coverage' : avail.length ? 'full_known_coverage' : 'no_available_fix',
      available_fixes: avail,
      remaining_findings: unresolved,
      consumption_bom_details: bom,
      unique_vulnerability_fix_count: unique(avail.map(a => a.advisory_id)).length,
      companion_artifact_count: bom ? bom.companion_artifacts.length : 0,
    };
  });

  return {
    schema_version: 'osera-backlog-snapshot/v1',
    read_only: true,
    metadata: {
      source_commit: sourceCommit,
      book_version: meta.book_version || 'unknown',
      view: meta.view || 'pinned_and_latest',
      commit_timestamp: commitTimestamp,
      snapshot_consistent: !dataQualityIssues.some(d => d.kind === 'inconsistent_snapshot'),
    },
    supported_lines: lineSummaries,
    backlog_items: backlogItems,
    exclusions,
    consumption_boms: consumptionBoms,
    data_quality_issues: dataQualityIssues,
  };
}

export function reconcileBacklogWithEstate(snapshot, estateObservations) {
  const ingested = snapshot.schema_version === 'osera-backlog-snapshot/v1' ? snapshot : ingestOseraBacklogSnapshot(snapshot);
  const rows = (estateObservations || []).map(obs => {
    const parsed = purl(obs.purl || '');
    const lib = parsed ? parsed.name.replace('/', ':') : obs.library;
    const deployedVersion = parsed?.version || obs.version || '';
    const deployedMinor = deriveMinorLine(deployedVersion);
    const candidateLines = ingested.supported_lines.filter(l => l.library === lib);
    const matchedLine = candidateLines.find(l => l.maintenance_line === deployedMinor) || null;
    const coordItems = ingested.backlog_items.filter(i => i.library === lib);
    const cves = splitList(obs.advisories || obs.cves);

    const itemMinorLine = item => item.maintenance_line || (item.fixed_by_version ? deriveMinorLine(item.fixed_by_version) : (item.fixed_by ? deriveMinorLine(purl(item.fixed_by)?.version) : ''));
    const isSameLineItem = item => {
      if (!matchedLine) return false;
      if (item.line_id && matchedLine.line_id && item.line_id === matchedLine.line_id) {
        const minor = itemMinorLine(item);
        return !minor || minor === deployedMinor;
      }
      return itemMinorLine(item) === deployedMinor;
    };

    const lineItems = coordItems.filter(isSameLineItem);
    const otherLineItems = coordItems.filter(i => !isSameLineItem(i));
    const matchesObservedCves = item => !cves.length || cves.includes(item.advisory_id) || (item.aliases || []).some(a => cves.includes(a));

    const exactPatchedItems = lineItems.filter(i =>
      i.availability_granted && (i.fixed_by_version === deployedVersion || String(i.fixed_by).endsWith(`@${deployedVersion}`))
    );
    const isPatched = deployedVersion.includes('-osera-') && exactPatchedItems.length > 0;

    let activeFindings = [...cves];
    const availableFixes = [];
    for (const item of lineItems) {
      if (!matchesObservedCves(item)) continue;
      if (item.status === 'fixed' && item.availability_granted) {
        if (isPatched && (item.fixed_by_version === deployedVersion || String(item.fixed_by).endsWith(`@${deployedVersion}`))) {
          activeFindings = activeFindings.filter(c => c !== item.advisory_id && !(item.aliases || []).includes(c));
        } else {
          availableFixes.push({
            advisory_id: item.advisory_id,
            backlog_status: 'fixed',
            maintenance_line: itemMinorLine(item) || deployedMinor,
            fixed_by: item.fixed_by,
            consume_coordinate: item.consume_coordinate,
          });
        }
      }
    }

    const crossLineMigrationOptions = otherLineItems
      .filter(i => matchesObservedCves(i) && i.status === 'fixed' && i.availability_granted)
      .map(i => ({
        advisory_id: i.advisory_id,
        maintenance_line: itemMinorLine(i),
        line_id: i.line_id,
        fixed_by: i.fixed_by,
        consume_coordinate: i.consume_coordinate,
      }))
      .sort((a, b) => String(a.maintenance_line || '').localeCompare(String(b.maintenance_line || '')) ||
        String(a.advisory_id || '').localeCompare(String(b.advisory_id || '')) ||
        String(a.fixed_by || '').localeCompare(String(b.fixed_by || '')));

    availableFixes.sort((a, b) => String(a.advisory_id || '').localeCompare(String(b.advisory_id || '')) ||
      String(a.fixed_by || '').localeCompare(String(b.fixed_by || '')));

    const coverageStatus = matchedLine ? 'supported_maintenance_line' : 'unsupported_maintenance_line';
    let memberDeploymentState;
    if (!matchedLine) {
      memberDeploymentState = activeFindings.length ? 'deployed_vulnerable_unsupported_line' : 'deployed_unsupported_line';
    } else if (isPatched && !activeFindings.length) {
      memberDeploymentState = 'observed_patched';
    } else if (isPatched && activeFindings.length) {
      memberDeploymentState = 'partially_patched_with_residual_findings';
    } else if (availableFixes.length) {
      memberDeploymentState = 'deployed_vulnerable_fix_available';
    } else {
      memberDeploymentState = 'deployed_vulnerable_no_available_fix';
    }

    return {
      application_id: obs.application_id || obs.project || 'app',
      library: lib,
      deployed_version: deployedVersion,
      deployed_maintenance_line: deployedMinor,
      matched_line_id: matchedLine?.line_id || null,
      coverage_status: coverageStatus,
      pinned_baseline: matchedLine?.pinned_baseline || null,
      latest_patch_resolution: matchedLine?.latest_patch || null,
      consume_coordinate: matchedLine?.consume_coordinate || null,
      consumption_bom: matchedLine?.consumption_bom_details || null,
      member_deployment_state: memberDeploymentState,
      deployed_findings_cleared_by_reference_graph: false,
      active_deployed_findings: activeFindings,
      available_fixes: availableFixes,
      cross_line_migration_options: crossLineMigrationOptions,
      excluded_findings: lineItems
        .filter(i => i.status === 'excluded')
        .map(i => ({ advisory_id: i.advisory_id, remediated_in_estate: false }))
        .sort((a, b) => String(a.advisory_id || '').localeCompare(String(b.advisory_id || ''))),
    };
  });
  return { schema_version: 'osera-backlog-snapshot/v1', rows, data_quality_issues: ingested.data_quality_issues };
}
