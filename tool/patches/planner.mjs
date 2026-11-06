// Deterministic opportunity ranking (#26) and actionable queue + portfolio planner (#27) shared by UI and export.
import { purl, unique } from './catalog.mjs';

const PRIORITY_ORDER = { P0: 0, P1: 1, P2: 2, P3: 3, UNRANKED: 9 };
const EFFORT_ORDER = { low: 1, medium: 2, high: 3, unknown: 4 };
const CRITICALITY_WEIGHT = { tier_1_critical: 30, high: 20, medium: 10, low: 0, unknown: 5 };

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

  const evaluated = rawOpportunities.map((opp, idx) => {
    const oppId = String(opp.opportunity_id || `opp-${idx + 1}`);
    const advisories = Array.isArray(opp.advisories) ? opp.advisories : [];
    const oseraEval = evaluateOseraPriority(advisories, rulesCfg);
    if (oseraEval.unknown_signal_advisories.length) hasIncompleteSignals = true;

    const apps = unique((opp.affected_applications || []).map(a => String(a).trim()));
    const canonAdvIds = unique(advisories.map(a => canonicalAdv(a.id || a.cve_id || a.advisory_id || '')));
    canonAdvIds.forEach(a => allAdvisories.add(a));
    apps.forEach(a => allApps.add(a));

    const exposureInstances = unique(
      Array.isArray(opp.exposure_instances) && opp.exposure_instances.length
        ? opp.exposure_instances.map(e => typeof e === 'string'
            ? `${e.split('|')[0]}|${canonicalAdv(e.split('|')[1])}`
            : `${e.application_id}|${canonicalAdv(e.advisory_id)}`)
        : apps.flatMap(app => canonAdvIds.map(adv => `${app}|${adv}`))
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
    const residualAdvs = eligible
      ? unique([...canonAdvIds.filter(a => !fixedCanon.has(a)), ...(selOpt?.residual_advisories || []).map(canonicalAdv)])
      : [...canonAdvIds];
    const addressedExposures = exposureInstances.filter(e => addressedAdvs.includes(e.split('|')[1]));
    const residualExposures = exposureInstances.filter(e => !addressedAdvs.includes(e.split('|')[1]));

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

  return {
    schema_version: 'osera-opportunity-planner/v1',
    data_completeness_state: hasIncompleteSignals ? 'incomplete_signals' : 'complete',
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
  const ready = rankedResult?.queues?.ready_to_plan || (rankedResult?.opportunities || []).filter(o => o.eligible_for_ready_ranking);
  const selected = ready.filter(opp =>
    (!filters.selected_opportunity_ids || filters.selected_opportunity_ids.includes(opp.opportunity_id)) &&
    (!filters.owner || opp.owner.toLowerCase() === filters.owner.toLowerCase()) &&
    (!filters.framework_or_runtime || opp.framework_or_runtime.toLowerCase() === filters.framework_or_runtime.toLowerCase()) &&
    (!filters.change_window || opp.change_window.toLowerCase() === filters.change_window.toLowerCase())
  );

  const cumulativeAddressed = new Set(), allScopeExposures = new Set();
  selected.forEach(o => (o.exposure_instances || []).forEach(e => allScopeExposures.add(e)));
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

  const residualExposures = [...allScopeExposures].filter(e => !cumulativeAddressed.has(e)).sort();
  return {
    schema_version: 'osera-opportunity-planner/v1',
    filters,
    selected_count: selected.length,
    incremental_actions: incrementalActions,
    portfolio_metrics: {
      affected_application_count: unique([...allScopeExposures].map(e => e.split('|')[0])).length,
      total_scope_exposure_instances: allScopeExposures.size,
      naive_unioned_claim_sum: rawSumClaimed,
      deduplicated_addressed_exposure_instances: cumulativeAddressed.size,
      duplicate_overlap_prevented: rawSumClaimed - cumulativeAddressed.size,
      residual_exposure_instance_count: residualExposures.length,
      addressed_unique_advisories: unique([...cumulativeAddressed].map(e => e.split('|')[1])),
      residual_unique_advisories: unique(residualExposures.map(e => e.split('|')[1])),
    },
    deduplicated_addressed_exposures: [...cumulativeAddressed].sort(),
    residual_exposures: residualExposures,
  };
}

export function exportOwnerChangePackage(rankedResult, portfolioPlan) {
  const byId = Object.fromEntries((rankedResult?.opportunities || []).map(o => [o.opportunity_id, o]));
  return {
    schema_version: 'osera-owner-change-package/v1',
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
}
