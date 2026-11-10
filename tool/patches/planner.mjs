// Deterministic opportunity ranking (#26) and actionable queue + portfolio planner (#27) shared by UI and export.
import { purl, unique } from './catalog.mjs';

const PRIORITY_ORDER = { P0: 0, P1: 1, P2: 2, P3: 3, UNRANKED: 9 };
const EFFORT_ORDER = { low: 1, medium: 2, high: 3, unknown: 4 };
const CRITICALITY_WEIGHT = { tier_1_critical: 30, high: 20, medium: 10, low: 0, unknown: 5 };

const splitExposureKey = exp => {
  const raw = String(exp || '').trim();
  const idx = raw.lastIndexOf('|');
  if (idx === -1) return [raw, ''];
  return [raw.slice(0, idx).trim(), raw.slice(idx + 1).trim()];
};

const extractAppIdFromPrefix = prefix => {
  const raw = String(prefix || '');
  const idx = raw.indexOf('@@');
  return idx === -1 ? raw : raw.slice(0, idx);
};

const stableCanonicalJson = val => {
  if (val === null || typeof val !== 'object') return JSON.stringify(val);
  if (Array.isArray(val)) return `[${val.map(stableCanonicalJson).join(',')}]`;
  const keys = Object.keys(val).sort();
  return `{${keys.map(k => `${JSON.stringify(k)}:${stableCanonicalJson(val[k])}`).join(',')}}`;
};

const deterministicHash = data => {
  const str = stableCanonicalJson(data);
  let h1 = 0xdeadbeef ^ str.length, h2 = 0x41c6ce57 ^ str.length;
  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return `fnv64:${(h2 >>> 0).toString(16).padStart(8, '0')}${(h1 >>> 0).toString(16).padStart(8, '0')}`;
};

const computeBaselineHashes = (opportunities, rulesCfg, policy, selectedIds = null) => {
  const sortedOpps = [...(opportunities || [])].sort((a, b) => String(a.opportunity_id || '').localeCompare(String(b.opportunity_id || '')));
  const estateProjection = sortedOpps.map(o => ({
    opportunity_id: o.opportunity_id,
    deployed_purl: o.deployed_purl,
    affected_applications: [...(o.affected_applications || [])].sort(),
    unique_advisories: [...(o.unique_advisories || [])].sort(),
    exposure_instances: [...(o.exposure_instances || [])].sort(),
  }));
  const catalogProjection = sortedOpps.map(o => ({
    opportunity_id: o.opportunity_id,
    target_purl: o.target_purl,
    provider: o.provider,
    queue: o.queue,
    eligible_for_ready_ranking: o.eligible_for_ready_ranking,
    choices: o.comparison_drawer?.choices || [],
  }));
  const estateHash = deterministicHash(estateProjection);
  const catalogHash = deterministicHash(catalogProjection);
  const rulesPolicyHash = deterministicHash({ osera_rules: rulesCfg || {}, company_policy: policy || {} });
  const planHash = deterministicHash({
    estate_snapshot_hash: estateHash,
    catalog_options_hash: catalogHash,
    rules_and_policy_hash: rulesPolicyHash,
    selected_opportunity_ids: Array.isArray(selectedIds) ? [...selectedIds].sort() : 'all_ready',
  });
  return {
    estate_snapshot_hash: estateHash,
    catalog_options_hash: catalogHash,
    rules_and_policy_hash: rulesPolicyHash,
    plan_baseline_hash: planHash,
  };
};

export function evaluateOseraPriority(advisories = [], rulesConfig = {}) {
  const rulesVersion = String(rulesConfig.rules_version || '2026.10-osera-prioritisation-v1');
  if (!Array.isArray(advisories) || !advisories.length) {
    return {
      included: false,
      priority: 'UNRANKED',
      rule_id: 'OSERA-NONE',
      rules_version: rulesVersion,
      reason: 'No vulnerability advisories observed on component.',
      unknown_signal_advisories: [],
      signal_summary: {
        kev_count: 0,
        max_cvss_score: 'unknown',
        max_epss_probability: 'unknown',
        max_epss_percentile: 'unknown',
        cvss_provenance: [],
      },
    };
  }

  const kevIds = [], p0Reasons = [], p1Reasons = [], p2Reasons = [], unknownIds = [], cvssProvenance = [];
  let maxCvss = null, maxEpssProb = null, maxEpssPct = null;

  for (const adv of advisories) {
    const id = String(adv.id || adv.cve_id || adv.advisory_id || 'UNKNOWN').trim();
    const isKev = Boolean(adv.kev);
    const cvssScore = typeof (adv.cvss_score ?? adv.cvss) === 'number' ? Number(adv.cvss_score ?? adv.cvss) : null;
    const cvssVer = String(adv.cvss_version || (cvssScore !== null ? '3.1' : 'unknown'));
    const cvssSrc = String(adv.cvss_source || (cvssScore !== null ? 'NVD/OSV' : 'unknown'));
    const epssProb = typeof adv.epss_probability === 'number' ? Number(adv.epss_probability) : null;
    const epssPct = typeof adv.epss_percentile === 'number' ? Number(adv.epss_percentile) : null;
    const signal = String(adv.exploit_maturity || adv.signal || '').toLowerCase();

    cvssProvenance.push({
      advisory_id: id,
      cvss_score: cvssScore ?? 'unknown',
      cvss_version: cvssVer,
      cvss_source: cvssSrc,
      epss_probability: epssProb ?? 'unknown',
      epss_percentile: epssPct ?? 'unknown',
    });

    if (cvssScore === null || (epssProb === null && epssPct === null)) unknownIds.push(id);
    if (cvssScore !== null && (maxCvss === null || cvssScore > maxCvss)) maxCvss = cvssScore;
    if (epssProb !== null && (maxEpssProb === null || epssProb > maxEpssProb)) maxEpssProb = epssProb;
    if (epssPct !== null && (maxEpssPct === null || epssPct > maxEpssPct)) maxEpssPct = epssPct;

    if (isKev) {
      kevIds.push(id);
      p0Reasons.push(`${id}: CISA KEV active exploitation catalog (OSERA-P0-KEV)`);
    } else if (cvssScore !== null && cvssScore >= 9.0) {
      p0Reasons.push(`${id}: Critical CVSS ${cvssScore.toFixed(1)} v${cvssVer} (OSERA-P0-CRITICAL)`);
    } else if (cvssScore !== null && cvssScore >= 7.0 && ((epssProb !== null && epssProb >= 0.20) || (epssPct !== null && epssPct >= 0.95))) {
      p0Reasons.push(`${id}: High CVSS ${cvssScore.toFixed(1)} with elevated EPSS (OSERA-P0-HIGH-EPSS)`);
    } else if (cvssScore !== null && cvssScore >= 7.0) {
      p1Reasons.push(`${id}: High CVSS ${cvssScore.toFixed(1)} v${cvssVer} (OSERA-P1-HIGH)`);
    } else if (cvssScore !== null && cvssScore >= 4.0 && cvssScore < 7.0 &&
               ((epssProb !== null && epssProb >= 0.08) || (epssPct !== null && epssPct >= 0.90) || ['poc', 'active', 'weaponized', 'high', 'epss_spike'].includes(signal))) {
      p1Reasons.push(`${id}: Medium CVSS ${cvssScore.toFixed(1)} with exploitability signal (OSERA-P1-MEDIUM-WITH-SIGNAL)`);
    } else if (cvssScore === null) {
      p2Reasons.push(`${id}: Missing CVSS score treated as unknown severity, never zero risk (OSERA-P2-UNKNOWN-SEVERITY)`);
    } else {
      p2Reasons.push(`${id}: Standard Medium/Low CVSS ${cvssScore.toFixed(1)} (OSERA-P2-BASELINE)`);
    }
  }

  let priority = 'P2', ruleId = 'OSERA-P2-BASELINE', reason = p2Reasons.join('; ');
  if (p0Reasons.length) {
    priority = 'P0';
    ruleId = kevIds.length ? 'OSERA-P0-KEV' : 'OSERA-P0-CRITICAL-OR-HIGH-EPSS';
    reason = p0Reasons.join('; ');
  } else if (p1Reasons.length) {
    priority = 'P1';
    ruleId = p1Reasons.some(r => r.includes('OSERA-P1-MEDIUM-WITH-SIGNAL')) ? 'OSERA-P1-MEDIUM-WITH-SIGNAL' : 'OSERA-P1-HIGH';
    reason = p1Reasons.join('; ');
  }

  return {
    included: true,
    priority,
    rule_id: ruleId,
    rules_version: rulesVersion,
    reason,
    unknown_signal_advisories: unique(unknownIds),
    signal_summary: {
      kev_count: kevIds.length,
      max_cvss_score: maxCvss ?? 'unknown',
      max_epss_probability: maxEpssProb ?? 'unknown',
      max_epss_percentile: maxEpssPct ?? 'unknown',
      cvss_provenance: cvssProvenance,
    },
  };
}

export function rankPatchOpportunities(payload, companyPolicy = null) {
  const rawOpportunities = Array.isArray(payload?.opportunities) ? payload.opportunities : [];
  const rulesCfg = payload?.osera_rules || {};
  const policy = companyPolicy || payload?.company_policy || {};

  if (!rawOpportunities.length) {
    return {
      schema_version: 'osera-opportunity-planner/v1',
      data_completeness_state: 'empty_inventory',
      opportunities: [],
      queues: { ready_to_plan: [], blocked: [], investigate: [], request_coverage: [] },
      rank_changes: [],
      summary_metrics: {
        total_opportunities: 0, ready_to_plan_count: 0, blocked_count: 0, investigate_count: 0,
        request_coverage_count: 0, unique_advisory_count: 0, affected_application_count: 0,
        exposure_instance_count: 0, unknown_signal_opportunity_count: 0,
      },
    };
  }

  const aliasMap = new Map();
  for (const opp of rawOpportunities) {
    for (const adv of opp.advisories || []) {
      const id = String(adv.id || adv.cve_id || adv.advisory_id || '').trim();
      for (const al of adv.aliases || []) if (id && al) aliasMap.set(String(al).trim(), id);
    }
  }
  const canonicalAdv = id => aliasMap.get(String(id).trim()) || String(id).trim();

  const allAdvisories = new Set(), allApps = new Set(), allExposures = new Set();
  let hasIncompleteSignals = false;

  const nonBomAppAdvCounts = new Map();
  for (const opp of rawOpportunities) {
    const actionKind = String(opp.action_kind || 'library_patch').trim().toLowerCase();
    if (actionKind === 'framework_bom_patch') continue;
    const appsPre = unique((opp.affected_applications || []).map(a => String(a).trim()).filter(Boolean));
    const advsPre = unique((opp.advisories || []).map(a => canonicalAdv(a.id || a.cve_id || a.advisory_id || '')).filter(Boolean));
    const seenPairs = new Set();
    if (Array.isArray(opp.exposure_instances) && opp.exposure_instances.length) {
      for (const e of opp.exposure_instances) {
        if (typeof e === 'string') {
          const [rawPref, advRaw] = splitExposureKey(e);
          seenPairs.add(`${extractAppIdFromPrefix(rawPref)}|||${canonicalAdv(advRaw)}`);
        } else if (e && typeof e === 'object') {
          seenPairs.add(`${String(e.application_id || 'app').trim()}|||${canonicalAdv(e.advisory_id || '')}`);
        }
      }
    } else {
      for (const a of appsPre) for (const v of advsPre) seenPairs.add(`${a}|||${v}`);
    }
    for (const pair of seenPairs) nonBomAppAdvCounts.set(pair, (nonBomAppAdvCounts.get(pair) || 0) + 1);
  }

  const evaluated = rawOpportunities.map((opp, idx) => {
    const oppId = String(opp.opportunity_id || `opp-${idx + 1}`);
    const actionKind = String(opp.action_kind || 'library_patch');
    const advisories = Array.isArray(opp.advisories) ? opp.advisories : [];
    const oseraEval = evaluateOseraPriority(advisories, rulesCfg);
    if (oseraEval.unknown_signal_advisories.length) hasIncompleteSignals = true;

    const apps = unique((opp.affected_applications || []).map(a => String(a).trim()).filter(Boolean));
    const canonAdvIds = unique(advisories.map(a => canonicalAdv(a.id || a.cve_id || a.advisory_id || '')).filter(Boolean));
    canonAdvIds.forEach(a => allAdvisories.add(a));
    apps.forEach(a => allApps.add(a));

    const oppOccId = String(opp.occurrence_id || opp.deployment_id || opp.module_id || opp.application_version_id || '').trim();
    const oppCompDisc = String(opp.deployed_purl || opp.library || oppId).trim();
    const makePrefix = (appId, explicitOcc, advId, compHint = '') => {
      const needsCompDisc = actionKind.toLowerCase() !== 'framework_bom_patch' && (nonBomAppAdvCounts.get(`${appId}|||${advId}`) || 0) > 1;
      const disc = String(compHint || oppCompDisc).trim();
      if (explicitOcc) {
        if ((needsCompDisc || compHint) && disc && !explicitOcc.split('@@').includes(disc)) {
          return `${appId}@@${explicitOcc}@@${disc}`;
        }
        return `${appId}@@${explicitOcc}`;
      }
      if (needsCompDisc || compHint) return `${appId}@@${disc}`;
      return appId;
    };

    const prefixesByApp = new Map();
    const recordPrefix = (appId, pref) => {
      if (!prefixesByApp.has(appId)) prefixesByApp.set(appId, new Set());
      prefixesByApp.get(appId).add(pref);
    };

    const exposureInstances = unique(
      Array.isArray(opp.exposure_instances) && opp.exposure_instances.length
        ? opp.exposure_instances.map(e => {
            if (typeof e === 'string') {
              const [rawPref, advRaw] = splitExposureKey(e);
              const appId = extractAppIdFromPrefix(rawPref);
              const explicitOcc = rawPref.includes('@@') ? rawPref.slice(rawPref.indexOf('@@') + 2) : oppOccId;
              const advId = canonicalAdv(advRaw);
              const pref = makePrefix(appId, explicitOcc, advId);
              allApps.add(appId);
              recordPrefix(appId, pref);
              return `${pref}|${advId}`;
            }
            const appId = String(e.application_id || 'app').trim();
            const advId = canonicalAdv(e.advisory_id || '');
            const occParts = [];
            for (const cand of [e.occurrence_id, e.deployment_id, e.module_id]) {
              const cStr = String(cand || '').trim();
              if (cStr && !occParts.includes(cStr)) occParts.push(cStr);
            }
            if (!occParts.length && oppOccId) occParts.push(oppOccId);
            const explicitOcc = occParts.join('@@');
            const compHint = String(e.component_purl || e.component || e.library || '').trim();
            const pref = makePrefix(appId, explicitOcc, advId, compHint);
            allApps.add(appId);
            recordPrefix(appId, pref);
            return `${pref}|${advId}`;
          })
        : apps.flatMap(app => canonAdvIds.map(adv => {
            const pref = makePrefix(app, oppOccId, adv);
            recordPrefix(app, pref);
            return `${pref}|${adv}`;
          }))
    );
    exposureInstances.forEach(e => allExposures.add(e));

    const options = Array.isArray(opp.options) ? opp.options : [];
    const selOpt = opp.selected_option || options.find(o => o.ready === true) || options[0] || null;
    const identityStatus = String(opp.identity_status || 'confirmed').toLowerCase();
    const blockers = unique([...(opp.blockers || []), ...(selOpt?.blocked_reasons || [])]);

    let queue = 'ready_to_plan', eligible = true, nextStep = '', evidenceNeeded = [];
    if (['ambiguous', 'unverified', 'missing_version', 'unknown'].includes(identityStatus)) {
      queue = 'investigate'; eligible = false;
      if (!blockers.includes('ambiguous_package_identity')) blockers.push('ambiguous_package_identity');
      nextStep = 'Resolve exact package PURL, version, and dependency graph from lockfile or build SBOM.';
      evidenceNeeded = ['build_sbom_with_exact_purl', 'resolved_dependency_lockfile'];
    } else if (!options.length) {
      queue = 'request_coverage'; eligible = false;
      if (!blockers.includes('no_known_patch_in_catalog')) blockers.push('no_known_patch_in_catalog');
      nextStep = 'Add maintenance line and unresolved CVEs to the OSERA Patch Request Cart (#29 / #42).';
      evidenceNeeded = ['osera_coverage_request_submission', 'provider_patch_publication'];
    } else if (!selOpt?.ready || blockers.length) {
      queue = 'blocked'; eligible = false;
      nextStep = `Resolve blocking condition(s) (${blockers.join(', ')}) or select an alternative provider option.`;
      evidenceNeeded = blockers.map(b => b.includes('entitlement') ? 'active_commercial_entitlement_in_member_overlay' : 'signed_artifact_promotion_and_vex_attestation');
    } else {
      nextStep = `Assign owner and schedule adoption of ${selOpt.replacement_purl} in change window.`;
      evidenceNeeded = ['post_deployment_sbom_verification'];
    }

    const fixedCanon = new Set(((selOpt?.fixed_advisories || []).concat(selOpt?.aliases || [])).map(canonicalAdv));
    const addressedAdvs = eligible ? canonAdvIds.filter(a => fixedCanon.has(a)) : [];
    const targetOnlyResidualAdvs = eligible
      ? unique((selOpt?.residual_advisories || []).map(canonicalAdv).filter(rc => rc && !canonAdvIds.includes(rc)))
      : [];
    const residualAdvs = eligible
      ? unique([...canonAdvIds.filter(a => !fixedCanon.has(a)), ...(selOpt?.residual_advisories || []).map(canonicalAdv).filter(Boolean)])
      : [...canonAdvIds];
    const addressedExposures = exposureInstances.filter(e => addressedAdvs.includes(splitExposureKey(e)[1]));
    const residualExposureSet = new Set(exposureInstances.filter(e => !addressedAdvs.includes(splitExposureKey(e)[1])));
    for (const targetRc of targetOnlyResidualAdvs) {
      const targetApps = apps.length ? apps : [...prefixesByApp.keys()];
      for (const appId of targetApps) {
        const prefs = prefixesByApp.has(appId) ? [...prefixesByApp.get(appId)] : [makePrefix(appId, oppOccId, targetRc)];
        for (const pref of prefs) residualExposureSet.add(`${pref}|${targetRc}`);
      }
    }
    const residualExposures = [...residualExposureSet].sort();

    const depScopeRaw = String(opp.dependency_scope || opp.direct_relationship || 'unknown').toLowerCase();
    const depScope = ['true', 'direct'].includes(depScopeRaw) ? 'direct' : (['false', 'transitive'].includes(depScopeRaw) ? 'transitive' : 'unknown');
    const parsedTarget = selOpt?.replacement_purl ? purl(selOpt.replacement_purl) : null;
    const recipeGuidance = !eligible
      ? { dependency_scope: depScope, recipe_status: 'unavailable_option_not_ready', openrewrite_recipe: null, instructions: 'Resolve blockers or request patch coverage before generating build instructions.' }
      : ['transitive', 'unknown'].includes(depScope)
        ? { dependency_scope: depScope, recipe_status: `suppressed_${depScope}_dependency_path`, openrewrite_recipe: null, instructions: `Direct-dependency OpenRewrite recipe suppressed for '${depScope}' path.` }
        : { dependency_scope: 'direct', recipe_status: 'supported_direct_maven_recipe', openrewrite_recipe: { type: 'specs.openrewrite.org/v1beta/recipe', target: selOpt.replacement_purl }, instructions: `Apply OpenRewrite UpgradeDependencyVersion for ${ parsedTarget?.exact || selOpt.replacement_purl }.` };

    const estEffort = String(selOpt?.estimated_effort || selOpt?.effort || opp.estimated_effort || 'medium').toLowerCase();
    const confidence = String(opp.confidence || (oseraEval.unknown_signal_advisories.length ? 'medium' : 'high')).toLowerCase();
    const measuredOutcome = String(opp.measured_outcome || 'not_yet_deployed').toLowerCase();

    const oseraBaseScore = (oseraEval.priority === 'P0' ? 300 : oseraEval.priority === 'P1' ? 200 : 100) +
      addressedExposures.length * 5 - (EFFORT_ORDER[estEffort] || 2);

    const criticality = String(opp.business_criticality || 'medium').toLowerCase();
    const internetExposed = Boolean(opp.internet_exposed);
    const slaDays = opp.sla_days_remaining;
    const changeWindow = String(opp.change_window || 'standard_weekly');
    let companyDelta = 0;
    const companyReasons = [];
    if (Object.keys(policy).length) {
      const w = (policy.criticality_weights || CRITICALITY_WEIGHT)[criticality] ?? 0;
      if (w > 0) { companyDelta += w; companyReasons.push(`business_criticality=${criticality} (+${w})`); }
      if (internetExposed && policy.boost_internet_exposed !== false) {
        const b = policy.internet_exposure_boost ?? 45;
        companyDelta += b; companyReasons.push(`internet_exposed=true (+${b})`);
      }
      if (typeof slaDays === 'number' && slaDays <= (policy.urgent_sla_threshold_days ?? 7)) {
        const sb = policy.urgent_sla_boost ?? 60;
        companyDelta += sb; companyReasons.push(`sla_days_remaining=${slaDays}d (+${sb})`);
      }
      if ((policy.frozen_change_windows || []).includes(changeWindow)) {
        const pen = policy.change_freeze_penalty ?? 50;
        companyDelta -= pen; companyReasons.push(`change_window=${changeWindow} constrained (-${pen})`);
      }
    }
    const companyScore = oseraBaseScore + companyDelta;
    const companyPriority = companyScore >= 280 ? 'P0' : companyScore >= 190 ? 'P1' : 'P2';

    const choices = options.map(opt => {
      const pid = String(opt.patch_id || opt.replacement_purl || '');
      const isSelected = Boolean(selOpt && pid === String(selOpt.patch_id || selOpt.replacement_purl || '') && opt.ready);
      const fSet = new Set(((opt.fixed_advisories || []).concat(opt.aliases || [])).map(canonicalAdv));
      const rem = canonAdvIds.filter(a => !fSet.has(a));
      return {
        patch_id: pid,
        provider: String(opt.provider || 'Unknown'),
        provider_kind: String(opt.provider_kind || 'upstream').toLowerCase(),
        replacement_purl: String(opt.replacement_purl || ''),
        ready: Boolean(opt.ready),
        selected: isSelected,
        addressed_advisories: canonAdvIds.filter(a => fSet.has(a)),
        remaining_advisories: rem,
        rejection_reasons: isSelected ? [] : (!opt.ready ? (opt.blocked_reasons || ['option_not_ready']) : [opt.rejection_reason || (rem.length ? `leaves_residual_advisories:${rem.join(',')}` : 'alternative_ready_option_selected_by_policy')]),
      };
    });

    return {
      opportunity_id: oppId,
      action_kind: String(opp.action_kind || 'library_patch'),
      library: String(opp.library || ''),
      deployed_purl: String(opp.deployed_purl || ''),
      framework_or_runtime: String(opp.framework_or_runtime || 'jvm-standard'),
      owner: String(opp.owner || 'unassigned'),
      change_window: changeWindow,
      queue,
      eligible_for_ready_ranking: eligible,
      source_priority: oseraEval.priority,
      source_priority_rule: oseraEval.rule_id,
      company_priority: companyPriority,
      company_priority_reasons: companyReasons,
      osera_baseline_score: oseraBaseScore,
      company_urgency_score: companyScore,
      osera_baseline_rank: null,
      ready_rank: null,
      rank_changed_by_company_policy: false,
      rank_change_explanation: null,
      target_purl: selOpt?.replacement_purl || null,
      provider: selOpt?.provider || null,
      provider_kind: selOpt?.provider_kind || null,
      entitlement_status: selOpt?.entitlement_status || 'not_applicable',
      evidence_state: selOpt?.evidence_state || (eligible ? 'verified' : 'blocked'),
      distinct_counts: {
        unique_advisory_count: canonAdvIds.length,
        affected_application_count: apps.length,
        exposure_instance_count: exposureInstances.length,
        addressed_exposure_instance_count: addressedExposures.length,
        residual_exposure_instance_count: residualExposures.length,
      },
      affected_applications: apps,
      unique_advisories: canonAdvIds,
      addressed_advisories: addressedAdvs,
      residual_advisories: residualAdvs,
      exposure_instances: exposureInstances,
      addressed_exposure_instances: addressedExposures,
      residual_exposure_instances: residualExposures,
      signal_summary: oseraEval.signal_summary,
      unknown_signal_advisories: oseraEval.unknown_signal_advisories,
      estimated_effort: estEffort,
      confidence,
      measured_outcome: measuredOutcome,
      blockers,
      next_step: nextStep,
      evidence_needed: evidenceNeeded,
      recipe_guidance: recipeGuidance,
      comparison_drawer: {
        opportunity_id: oppId,
        selected_patch_id: eligible ? (selOpt?.patch_id || null) : null,
        providers_compared: unique(choices.map(c => c.provider_kind)),
        choices,
      },
      rollback_target: String(opp.deployed_purl || ''),
      required_validation: opp.required_validation || ['verify_artifact_digest_and_vex', 'run_integration_test_suite', 're_scan_deployed_sbom'],
    };
  });

  const readyOpps = evaluated.filter(o => o.eligible_for_ready_ranking);
  const baselineSorted = [...readyOpps].sort((a, b) =>
    ((PRIORITY_ORDER[a.source_priority] ?? 9) - (PRIORITY_ORDER[b.source_priority] ?? 9)) ||
    (b.osera_baseline_score - a.osera_baseline_score) ||
    a.opportunity_id.localeCompare(b.opportunity_id)
  );
  baselineSorted.forEach((o, i) => { o.osera_baseline_rank = i + 1; });

  const companySorted = [...readyOpps].sort((a, b) =>
    ((PRIORITY_ORDER[a.company_priority] ?? 9) - (PRIORITY_ORDER[b.company_priority] ?? 9)) ||
    (b.company_urgency_score - a.company_urgency_score) ||
    a.opportunity_id.localeCompare(b.opportunity_id)
  );
  const rankChanges = [];
  companySorted.forEach((o, i) => {
    o.ready_rank = i + 1;
    if (o.osera_baseline_rank !== o.ready_rank) {
      o.rank_changed_by_company_policy = true;
      o.rank_change_explanation = `Moved from OSERA baseline rank #${o.osera_baseline_rank} (${o.source_priority}) to company rank #${o.ready_rank} (${o.company_priority}): ${o.company_priority_reasons.join('; ') || 'Relative score shift'}`;
      rankChanges.push({
        opportunity_id: o.opportunity_id,
        library: o.library,
        source_priority: o.source_priority,
        company_priority: o.company_priority,
        osera_baseline_rank: o.osera_baseline_rank,
        company_ready_rank: o.ready_rank,
        why: o.rank_change_explanation,
      });
    } else {
      o.rank_change_explanation = `Retained rank #${o.ready_rank} (source_priority=${o.source_priority}, company_priority=${o.company_priority})`;
    }
  });

  const qRank = { blocked: 1, investigate: 2, request_coverage: 3 };
  const nonReady = evaluated.filter(o => !o.eligible_for_ready_ranking).sort((a, b) =>
    ((qRank[a.queue] ?? 9) - (qRank[b.queue] ?? 9)) ||
    ((PRIORITY_ORDER[a.source_priority] ?? 9) - (PRIORITY_ORDER[b.source_priority] ?? 9)) ||
    a.opportunity_id.localeCompare(b.opportunity_id)
  );
  const orderedAll = [...companySorted, ...nonReady];
  const queues = {
    ready_to_plan: orderedAll.filter(o => o.queue === 'ready_to_plan'),
    blocked: orderedAll.filter(o => o.queue === 'blocked'),
    investigate: orderedAll.filter(o => o.queue === 'investigate'),
    request_coverage: orderedAll.filter(o => o.queue === 'request_coverage'),
  };

  const baselineHashes = computeBaselineHashes(orderedAll, rulesCfg, policy);

  return {
    schema_version: 'osera-opportunity-planner/v1',
    data_completeness_state: hasIncompleteSignals ? 'incomplete_signals' : 'complete',
    baseline_hashes: baselineHashes,
    osera_rules: rulesCfg,
    company_policy: policy,
    opportunities: orderedAll,
    queues,
    rank_changes: rankChanges,
    summary_metrics: {
      total_opportunities: orderedAll.length,
      ready_to_plan_count: queues.ready_to_plan.length,
      blocked_count: queues.blocked.length,
      investigate_count: queues.investigate.length,
      request_coverage_count: queues.request_coverage.length,
      unique_advisory_count: allAdvisories.size,
      affected_application_count: allApps.size,
      exposure_instance_count: allExposures.size,
      unknown_signal_opportunity_count: orderedAll.filter(o => o.unknown_signal_advisories.length > 0).length,
    },
  };
}

export function assemblePortfolioPlan(rankedResult, filters = {}) {
  const allOpportunities = Array.isArray(rankedResult?.opportunities) && rankedResult.opportunities.length
    ? rankedResult.opportunities
    : Object.values(rankedResult?.queues || {}).flat().filter(Boolean);

  const matchesScopeFilters = opp =>
    (!filters.owner || String(opp.owner || '').toLowerCase() === filters.owner.toLowerCase()) &&
    (!filters.framework_or_runtime || String(opp.framework_or_runtime || '').toLowerCase() === filters.framework_or_runtime.toLowerCase()) &&
    (!filters.change_window || String(opp.change_window || '').toLowerCase() === filters.change_window.toLowerCase());

  const inScopeOpportunities = allOpportunities.filter(matchesScopeFilters);
  const ready = rankedResult?.queues?.ready_to_plan || allOpportunities.filter(o => o.eligible_for_ready_ranking);
  const selected = ready.filter(opp =>
    (!filters.selected_opportunity_ids || filters.selected_opportunity_ids.includes(opp.opportunity_id)) &&
    matchesScopeFilters(opp)
  );

  const cumulativeAddressed = new Set(), allScopeExposures = new Set(), targetResidualExposures = new Set();
  inScopeOpportunities.forEach(o => {
    (o.exposure_instances || []).forEach(e => allScopeExposures.add(e));
  });
  selected.forEach(o => {
    (o.exposure_instances || []).forEach(e => allScopeExposures.add(e));
    (o.residual_exposure_instances || []).forEach(e => targetResidualExposures.add(e));
  });
  let rawSumClaimed = 0;

  const incrementalActions = selected.map((opp, idx) => {
    const claimed = opp.addressed_exposure_instances || [];
    rawSumClaimed += claimed.length;
    const newlyAddressed = claimed.filter(e => !cumulativeAddressed.has(e)).sort();
    const overlapping = claimed.filter(e => cumulativeAddressed.has(e)).sort();
    claimed.forEach(e => cumulativeAddressed.add(e));
    return {
      step: idx + 1,
      opportunity_id: opp.opportunity_id,
      action_kind: opp.action_kind,
      library: opp.library,
      target_purl: opp.target_purl,
      provider: opp.provider,
      owner: opp.owner,
      change_window: opp.change_window,
      standalone_claimed_exposure_reduction: claimed.length,
      incremental_exposure_reduction: newlyAddressed.length,
      overlapping_exposure_instances_deduplicated: overlapping,
      newly_addressed_exposure_instances: newlyAddressed,
      residual_exposure_instances_on_component: opp.residual_exposure_instances,
      estimated_effort: opp.estimated_effort,
      confidence: opp.confidence,
      measured_outcome: opp.measured_outcome,
    };
  });

  const combinedScopeAndTargetResiduals = new Set([...allScopeExposures, ...targetResidualExposures]);
  const residualExposures = [...combinedScopeAndTargetResiduals].filter(e => !cumulativeAddressed.has(e)).sort();
  const baselineHashes = computeBaselineHashes(
    rankedResult?.opportunities || selected,
    rankedResult?.osera_rules || {},
    rankedResult?.company_policy || {},
    selected.map(o => o.opportunity_id)
  );
  return {
    schema_version: 'osera-opportunity-planner/v1',
    baseline_hashes: baselineHashes,
    filters,
    selected_count: selected.length,
    incremental_actions: incrementalActions,
    portfolio_metrics: {
      affected_application_count: unique([...combinedScopeAndTargetResiduals].map(e => extractAppIdFromPrefix(splitExposureKey(e)[0])).filter(Boolean)).length,
      total_scope_exposure_instances: allScopeExposures.size,
      naive_unioned_claim_sum: rawSumClaimed,
      deduplicated_addressed_exposure_instances: cumulativeAddressed.size,
      duplicate_overlap_prevented: rawSumClaimed - cumulativeAddressed.size,
      residual_exposure_instance_count: residualExposures.length,
      addressed_unique_advisories: unique([...cumulativeAddressed].map(e => splitExposureKey(e)[1]).filter(Boolean)),
      residual_unique_advisories: unique(residualExposures.map(e => splitExposureKey(e)[1]).filter(Boolean)),
    },
    deduplicated_addressed_exposures: [...cumulativeAddressed].sort(),
    residual_exposures: residualExposures,
  };
}

export function detectPlanSnapshotDrift(savedPlanOrPackage, currentRankedResult) {
  const savedHashes = savedPlanOrPackage?.baseline_hashes || {};
  const actions = savedPlanOrPackage?.incremental_actions || savedPlanOrPackage?.change_packages || [];
  const selectedIds = actions.map(a => a.opportunity_id).filter(Boolean);
  const currentHashes = computeBaselineHashes(
    currentRankedResult?.opportunities || [],
    currentRankedResult?.osera_rules || {},
    currentRankedResult?.company_policy || {},
    selectedIds.length ? selectedIds : null
  );
  const estateChanged = Boolean(savedHashes.estate_snapshot_hash && savedHashes.estate_snapshot_hash !== currentHashes.estate_snapshot_hash);
  const catalogChanged = Boolean(savedHashes.catalog_options_hash && savedHashes.catalog_options_hash !== currentHashes.catalog_options_hash);
  const rulesChanged = Boolean(savedHashes.rules_and_policy_hash && savedHashes.rules_and_policy_hash !== currentHashes.rules_and_policy_hash);
  const currentById = Object.fromEntries((currentRankedResult?.opportunities || []).map(o => [o.opportunity_id, o]));
  const driftEvents = [];
  for (const act of actions) {
    const oppId = act.opportunity_id;
    const plannedTarget = act.target_purl || act.target_coordinate || '';
    const curr = currentById[oppId];
    if (!curr) {
      driftEvents.push({ opportunity_id: oppId, kind: 'opportunity_removed_from_snapshot' });
    } else if (!curr.eligible_for_ready_ranking || curr.queue !== 'ready_to_plan') {
      driftEvents.push({ opportunity_id: oppId, kind: 'target_option_withdrawn_or_blocked', current_queue: curr.queue, blockers: curr.blockers || [] });
    } else if (plannedTarget && curr.target_purl !== plannedTarget) {
      driftEvents.push({ opportunity_id: oppId, kind: 'recommended_target_coordinate_changed', planned_target: plannedTarget, current_target: curr.target_purl });
    }
  }
  return {
    drifted: Boolean(estateChanged || catalogChanged || rulesChanged || driftEvents.length),
    estate_snapshot_changed: estateChanged,
    catalog_options_changed: catalogChanged,
    rules_or_policy_changed: rulesChanged,
    saved_baseline_hashes: savedHashes,
    current_baseline_hashes: currentHashes,
    drift_events: driftEvents,
  };
}

export function exportOwnerChangePackageMarkdown(changePackage) {
  const m = changePackage?.portfolio_metrics || {};
  const h = changePackage?.baseline_hashes || {};
  const lines = [
    '# OSERA Owner-Ready Patch Change Package',
    '',
    `- **Schema Version**: \`${changePackage?.schema_version || 'osera-owner-change-package/v1'}\``,
    `- **Plan Baseline Hash**: \`${h.plan_baseline_hash || 'unknown'}\``,
    `- **Affected Applications**: ${m.affected_application_count ?? 0}`,
    `- **Deduplicated Exposure Reduction**: ${m.deduplicated_addressed_exposure_instances ?? 0}`,
    `- **Residual Exposure Instances**: ${m.residual_exposure_instance_count ?? 0}`,
    '',
    '## Planned Actions',
  ];
  (changePackage?.change_packages || []).forEach((pkg, idx) => {
    lines.push(
      `### ${idx + 1}. \`${pkg.opportunity_id}\` (${pkg.source_priority} -> ${pkg.company_priority})`,
      `- **Owner / Window**: \`${pkg.owner}\` / \`${pkg.change_window}\``,
      `- **Source Coordinate**: \`${pkg.source_coordinate}\``,
      `- **Target Coordinate**: \`${pkg.target_coordinate}\` (${pkg.provider})`,
      `- **Incremental Exposure Reduction**: ${pkg.incremental_exposure_reduction}`,
      `- **Residual Advisories**: ${(pkg.residual_advisories || []).join(', ') || 'None'}`,
      `- **Instructions**: ${pkg.implementation_instructions}`,
      `- **Rollback Target**: \`${pkg.rollback_target}\``,
      ''
    );
  });
  return lines.join('\n');
}

export function exportOwnerChangePackageCsv(changePackage) {
  const headers = [
    'opportunity_id', 'owner', 'change_window', 'framework_or_runtime', 'action_kind',
    'source_coordinate', 'target_coordinate', 'provider', 'source_priority', 'company_priority',
    'incremental_exposure_reduction', 'residual_advisories', 'recipe_status', 'rollback_target',
  ];
  const esc = v => {
    const s = String(v ?? '');
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const rows = [headers.join(',')];
  for (const pkg of changePackage?.change_packages || []) {
    rows.push([
      pkg.opportunity_id, pkg.owner, pkg.change_window, pkg.framework_or_runtime, pkg.action_kind,
      pkg.source_coordinate, pkg.target_coordinate, pkg.provider, pkg.source_priority, pkg.company_priority,
      pkg.incremental_exposure_reduction ?? 0, (pkg.residual_advisories || []).join(';'), pkg.recipe_status, pkg.rollback_target,
    ].map(esc).join(','));
  }
  return rows.join('\n') + '\n';
}

export function exportOwnerChangePackageCycloneDx(changePackage) {
  const components = [], vulnerabilities = [];
  for (const pkg of changePackage?.change_packages || []) {
    const ref = pkg.opportunity_id || pkg.target_coordinate;
    components.push({
      type: 'library',
      'bom-ref': ref,
      name: pkg.target_coordinate,
      purl: pkg.target_coordinate,
      properties: [
        { name: 'osera:source_coordinate', value: String(pkg.source_coordinate || '') },
        { name: 'osera:provider', value: String(pkg.provider || '') },
        { name: 'osera:owner', value: String(pkg.owner || '') },
        { name: 'osera:change_window', value: String(pkg.change_window || '') },
        { name: 'osera:rollback_target', value: String(pkg.rollback_target || '') },
      ],
    });
    for (const advId of pkg.selected_option_details?.addressed_advisories || []) {
      vulnerabilities.push({ id: advId, analysis: { state: 'resolved', detail: `Planned upgrade from ${pkg.source_coordinate} to ${pkg.target_coordinate}` }, affects: [{ ref }] });
    }
    for (const resId of pkg.residual_advisories || []) {
      vulnerabilities.push({ id: resId, analysis: { state: 'exploitable', detail: `Residual advisory remaining after upgrading to ${pkg.target_coordinate}` }, affects: [{ ref }] });
    }
  }
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    version: 1,
    metadata: { properties: [{ name: 'osera:plan_baseline_hash', value: String(changePackage?.baseline_hashes?.plan_baseline_hash || '') }] },
    components,
    vulnerabilities,
  };
}

export function exportOwnerChangePackage(rankedResult, portfolioPlan) {
  const byId = Object.fromEntries((rankedResult?.opportunities || []).map(o => [o.opportunity_id, o]));
  const result = {
    schema_version: 'osera-owner-change-package/v1',
    baseline_hashes: portfolioPlan?.baseline_hashes || rankedResult?.baseline_hashes || {},
    portfolio_metrics: portfolioPlan.portfolio_metrics,
    change_packages: (portfolioPlan.incremental_actions || []).map(item => {
      const opp = byId[item.opportunity_id] || {};
      const choices = opp.comparison_drawer?.choices || [];
      return {
        opportunity_id: opp.opportunity_id,
        owner: opp.owner,
        change_window: opp.change_window,
        framework_or_runtime: opp.framework_or_runtime,
        action_kind: opp.action_kind,
        source_coordinate: opp.deployed_purl,
        target_coordinate: opp.target_purl,
        provider: opp.provider,
        provider_kind: opp.provider_kind,
        entitlement_status: opp.entitlement_status,
        evidence_state: opp.evidence_state,
        source_priority: opp.source_priority,
        company_priority: opp.company_priority,
        affected_applications: opp.affected_applications,
        incremental_exposure_reduction: item.incremental_exposure_reduction,
        residual_advisories: opp.residual_advisories,
        implementation_instructions: opp.recipe_guidance?.instructions,
        recipe_status: opp.recipe_guidance?.recipe_status,
        openrewrite_recipe: opp.recipe_guidance?.openrewrite_recipe,
        required_validation: opp.required_validation,
        rollback_target: opp.rollback_target,
        selected_option_details: choices.find(c => c.selected) || null,
        rejected_alternatives: choices.filter(c => !c.selected),
      };
    }),
  };
  result.exports = {
    markdown: exportOwnerChangePackageMarkdown(result),
    csv: exportOwnerChangePackageCsv(result),
    cyclonedx_vex: exportOwnerChangePackageCycloneDx(result),
  };
  return result;
}
