// Track patch plans through deployment and verify realized remediation (#28), and export/deduplicate private estate coverage requests (#29, #42).
import { purl, unique } from './catalog.mjs';

const SUPPORTED_ECOSYSTEMS = new Set(['maven', 'npm', 'pypi', 'golang', 'nuget', 'cargo', 'composer', 'gem']);
const ADVISORY_RE = /^(?:CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})$/i;
const PRIVATE_KEYS = new Set([
  'application_id', 'applications', 'affected_applications', 'consumer_project_ids',
  'direct_consumer_project_ids', 'owner', 'owners', 'dependency_path', 'dependency_paths',
  'contract_id', 'pricing', 'internal_repository_url', 'scope_name',
]);

const extractLibCoord = rawPurl => {
  const parsed = rawPurl ? purl(rawPurl) : null;
  if (!parsed) return '';
  return parsed.type === 'maven' ? parsed.name.replace('/', ':') : parsed.name;
};

const canonicalJson = val => {
  if (val === null || typeof val !== 'object') return JSON.stringify(val);
  if (Array.isArray(val)) return `[${val.map(canonicalJson).join(',')}]`;
  const keys = Object.keys(val).sort();
  return `{${keys.map(k => `${JSON.stringify(k)}:${canonicalJson(val[k])}`).join(',')}}`;
};

const parseIsoTimestampEpoch = rawTs => {
  const tsStr = String(rawTs || '').trim();
  if (!tsStr) return { valid: 0, epochMs: Number.NEGATIVE_INFINITY };
  const hasZone = /(?:Z|[+-]\d{2}:?\d{2})$/i.test(tsStr);
  const normalized = hasZone ? tsStr : `${tsStr}Z`;
  const ms = Date.parse(normalized);
  if (Number.isNaN(ms)) return { valid: 0, epochMs: Number.NEGATIVE_INFINITY };
  return { valid: 1, epochMs: ms };
};

const extractDeploymentId = obs => {
  const explicitDep = String(obs.deployment_id || '').trim();
  const locParts = [];
  for (const key of ['region', 'cluster', 'namespace', 'instance_id', 'host']) {
    const val = String(obs[key] || '').trim();
    if (val && !locParts.includes(val)) locParts.push(val);
  }
  if (explicitDep) {
    const extra = locParts.filter(p => p !== explicitDep && !explicitDep.split('/').includes(p));
    return extra.length ? [explicitDep, ...extra].join('/') : explicitDep;
  }
  return locParts.length ? locParts.join('/') : 'default';
};

const occurrenceMatchesTarget = (depId, obs, target) => {
  const t = String(target || '').trim();
  if (!t) return false;
  if (depId === t || depId.startsWith(`${t}/`) || depId.split('/').includes(t)) return true;
  for (const key of ['deployment_id', 'region', 'cluster', 'namespace', 'instance_id', 'host']) {
    if (String(obs[key] || '').trim() === t) return true;
  }
  return false;
};

export function reconcilePatchPlansWithObservations(bundle) {
  const staleCutoff = String(bundle.stale_inventory_cutoff || '2026-10-20T00:00:00Z');
  const cutoffParsed = parseIsoTimestampEpoch(staleCutoff);
  const withdrawnPurls = new Set(bundle.withdrawn_artifacts || []);
  const invalidatedAdvisories = new Set(bundle.invalidated_advisory_claims || []);

  // Index latest deployment observations by (application_id, environment, deployment_id, library_coord)
  const obsByOcc = new Map();
  for (const obs of bundle.deployment_observations || []) {
    if (!obs || typeof obs !== 'object') continue;
    const appId = String(obs.application_id || '').trim();
    if (!appId) continue;
    const obsEnv = String(obs.environment || 'production').trim().toLowerCase();
    const depId = extractDeploymentId(obs);
    const libCoord = String(obs.library || extractLibCoord(obs.observed_purl) || '*').trim();
    const occKey = `${appId}|||${obsEnv}|||${depId}|||${libCoord}`;
    const tsParsed = parseIsoTimestampEpoch(obs.observed_at);
    const cJson = canonicalJson(obs);
    const existing = obsByOcc.get(occKey);
    const isNewer = !existing ||
      tsParsed.valid > existing.tsValid ||
      (tsParsed.valid === existing.tsValid && tsParsed.epochMs > existing.tsEpoch) ||
      (tsParsed.valid === existing.tsValid && tsParsed.epochMs === existing.tsEpoch && cJson > existing.cJson);
    if (isNewer) {
      obsByOcc.set(occKey, { appId, obsEnv, depId, libCoord, tsValid: tsParsed.valid, tsEpoch: tsParsed.epochMs, cJson, obs });
    }
  }
  const sortedOccEntries = [...obsByOcc.values()].sort((a, b) =>
    a.appId.localeCompare(b.appId) || a.obsEnv.localeCompare(b.obsEnv) || a.depId.localeCompare(b.depId) || a.libCoord.localeCompare(b.libCoord)
  );

  let totalPlanned = 0, totalObserved = 0, totalDrift = 0;

  const plans = (bundle.plans || []).map(plan => {
    const planId = String(plan.plan_id || 'plan');
    const oppId = String(plan.opportunity_id || planId);
    const priorStage = String(plan.current_stage || 'planned').toLowerCase();
    const selectedPurl = String(plan.selected_artifact_purl || '');
    const selectedDigest = plan.selected_artifact_digest || null;
    const sourcePurl = String(plan.source_artifact_purl || '');
    const requiredEnv = String(plan.required_environment || 'production').toLowerCase();
    const planLibCoord = String(plan.library || extractLibCoord(selectedPurl) || extractLibCoord(sourcePurl) || '').trim();
    const targetDeployments = unique((plan.target_deployments || plan.target_regions || []).map(d => String(d).trim()).filter(Boolean)).sort();
    const targetApps = plan.target_applications || [];
    const expectedAdvs = plan.expected_fixed_advisories || [];
    const plannedExposures = targetDeployments.length
      ? targetApps.flatMap(app => {
          const appEnvOccsForPlan = sortedOccEntries.filter(e =>
            e.appId === app &&
            e.obsEnv === requiredEnv &&
            (!planLibCoord || e.libCoord === planLibCoord || e.libCoord === '*') &&
            e.obs.removed_from_scope !== true
          );
          const concreteDeps = unique(
            targetDeployments.flatMap(dep => {
              const matched = appEnvOccsForPlan.filter(e => occurrenceMatchesTarget(e.depId, e.obs, dep)).map(e => e.depId);
              return matched.length ? matched : [dep];
            })
          );
          return concreteDeps.flatMap(dep => expectedAdvs.map(adv => `${app}@${dep}|${adv}`));
        })
      : targetApps.flatMap(app => expectedAdvs.map(adv => `${app}|${adv}`));
    totalPlanned += plannedExposures.length;

    const ignoredSignals = {
      ticket_status: plan.ticket_status || 'open',
      osera_issue_status: plan.osera_issue_status || 'open',
      recipe_generated: Boolean(plan.recipe_generated),
      reference_graph_updated: Boolean(plan.reference_graph_updated),
    };

    if (priorStage === 'exception' || plan.exception_approved === true) {
      return {
        plan_id: planId, opportunity_id: oppId, selected_artifact_purl: selectedPurl,
        prior_stage: priorStage, reconciled_stage: 'exception', opportunity_reopened: false,
        reopened_reason: null, planned_benefit_exposures: plannedExposures,
        observed_remediated_exposures: [], residual_exposures: plannedExposures,
        inventory_or_scope_drift_exposures: [], non_deployment_signals_ignored: ignoredSignals,
      };
    }

    if (withdrawnPurls.has(selectedPurl) || plan.artifact_withdrawn === true) {
      return {
        plan_id: planId, opportunity_id: oppId, selected_artifact_purl: selectedPurl,
        prior_stage: priorStage, reconciled_stage: 'reopened_withdrawn_artifact', opportunity_reopened: true,
        reopened_reason: `Selected patch artifact ${selectedPurl} was withdrawn by provider; opportunity ${oppId} reopened.`,
        planned_benefit_exposures: plannedExposures, observed_remediated_exposures: [],
        residual_exposures: plannedExposures, inventory_or_scope_drift_exposures: [],
        non_deployment_signals_ignored: ignoredSignals,
      };
    }

    const verifiedApps = [], deployedUnverified = [], failedValidation = [], rolledBack = [], staleApps = [], unpatched = [], driftApps = [];
    const verifiedOccurrences = [], deployedUnverifiedOccurrences = [], failedValidationOccurrences = [],
      rolledBackOccurrences = [], staleInventoryOccurrences = [], unpatchedOccurrences = [], outOfScopeUnpatchedOccurrences = [];

    for (const app of targetApps) {
      const appEnvOccs = sortedOccEntries.filter(e =>
        e.appId === app &&
        e.obsEnv === requiredEnv &&
        (!planLibCoord || e.libCoord === planLibCoord || e.libCoord === '*')
      );
      let inScopeOccs = appEnvOccs;
      if (targetDeployments.length) {
        inScopeOccs = appEnvOccs.filter(e => targetDeployments.some(t => occurrenceMatchesTarget(e.depId, e.obs, t)));
        for (const outE of appEnvOccs.filter(e => !targetDeployments.some(t => occurrenceMatchesTarget(e.depId, e.obs, t)))) {
          if (String(outE.obs.observed_purl || '').trim() !== selectedPurl) {
            outOfScopeUnpatchedOccurrences.push(`${app}@${outE.depId}`);
          }
        }
      }
      const activeOccs = inScopeOccs.filter(e => e.obs.removed_from_scope !== true);
      if (!activeOccs.length) {
        driftApps.push(app);
        continue;
      }

      let appVerCount = 0, appDepUnverCount = 0, appFailCount = 0, appRbCount = 0, appStaleCount = 0, appUnpatchedCount = 0;
      for (const entry of activeOccs) {
        const { depId, obs, tsValid, tsEpoch } = entry;
        const occLabel = (targetDeployments.length || depId !== 'default' || activeOccs.length > 1) ? `${app}@${depId}` : app;
        const rawObsTs = String(obs.observed_at || '').trim();
        const isStale = Boolean(
          rawObsTs && (tsValid === 0 || (cutoffParsed.valid === 1 && tsEpoch < cutoffParsed.epochMs))
        );
        if (isStale) {
          appStaleCount++;
          staleInventoryOccurrences.push(occLabel);
        }
        const matches = obs.observed_purl === selectedPurl &&
          String(obs.environment || 'production').toLowerCase() === requiredEnv &&
          (!selectedDigest || obs.observed_artifact_digest === selectedDigest);
        if (matches) {
          if (obs.validation_status === 'failed') {
            appFailCount++;
            failedValidationOccurrences.push(occLabel);
          } else if (obs.validation_status === 'passed' && !isStale) {
            appVerCount++;
            verifiedOccurrences.push(occLabel);
          } else {
            appDepUnverCount++;
            deployedUnverifiedOccurrences.push(occLabel);
          }
        } else if ((obs.previously_deployed_target || priorStage === 'verified') && obs.observed_purl === sourcePurl) {
          appRbCount++;
          rolledBackOccurrences.push(occLabel);
        } else {
          appUnpatchedCount++;
          unpatchedOccurrences.push(occLabel);
        }
      }

      if (appStaleCount > 0) staleApps.push(app);
      if (appRbCount > 0) rolledBack.push(app);
      else if (appFailCount > 0) failedValidation.push(app);
      else if (appVerCount === activeOccs.length && appStaleCount === 0) verifiedApps.push(app);
      else if (appVerCount > 0 || appDepUnverCount > 0) {
        deployedUnverified.push(app);
        if (appUnpatchedCount > 0) unpatched.push(app);
      } else {
        unpatched.push(app);
      }
    }

    const observedRemediated = targetDeployments.length
      ? verifiedOccurrences.flatMap(occLabel => expectedAdvs.filter(a => !invalidatedAdvisories.has(a)).map(a => `${occLabel}|${a}`))
      : verifiedApps.flatMap(app => expectedAdvs.filter(a => !invalidatedAdvisories.has(a)).map(a => `${app}|${a}`));
    const driftExposures = targetDeployments.length
      ? driftApps.flatMap(app => targetDeployments.flatMap(dep => expectedAdvs.map(a => `${app}@${dep}|${a}`)))
      : driftApps.flatMap(app => expectedAdvs.map(a => `${app}|${a}`));
    const residualExposures = plannedExposures.filter(e => !observedRemediated.includes(e) && !driftExposures.includes(e));
    totalObserved += observedRemediated.length;
    totalDrift += driftExposures.length;

    let reconciledStage = 'planned', reopened = false, reopenedReason = null;
    if (rolledBack.length) {
      reconciledStage = 'reopened_rollback'; reopened = true;
      reopenedReason = `Deployment rollback detected on ${rolledBack.join(', ')}; opportunity ${oppId} reopened.`;
    } else if (failedValidation.length) {
      reconciledStage = 'validation_failed'; reopened = true;
      reopenedReason = `Post-deployment validation failed on ${failedValidation.join(', ')}.`;
    } else if (verifiedApps.length === targetApps.length && !residualExposures.length) {
      reconciledStage = 'verified';
    } else if (verifiedApps.length || deployedUnverified.length || verifiedOccurrences.length || deployedUnverifiedOccurrences.length) {
      const hasPartial = (verifiedApps.length < targetApps.length - driftApps.length) || unpatchedOccurrences.length > 0;
      reconciledStage = (staleApps.length || hasPartial)
        ? (staleApps.length ? 'partial_rollout_with_stale_inventory' : 'partial_rollout')
        : 'deployed';
    } else if (driftApps.length === targetApps.length) {
      reconciledStage = 'inventory_scope_drift_only';
    } else {
      reconciledStage = priorStage === 'tested' ? 'tested' : 'planned';
    }

    return {
      plan_id: planId, opportunity_id: oppId, selected_artifact_purl: selectedPurl,
      prior_stage: priorStage, reconciled_stage: reconciledStage, opportunity_reopened: reopened,
      reopened_reason: reopenedReason,
      application_breakdown: {
        verified_applications: verifiedApps,
        deployed_unverified_applications: deployedUnverified,
        failed_validation_applications: failedValidation,
        rolled_back_applications: rolledBack,
        stale_inventory_applications: staleApps,
        unpatched_applications: unpatched,
        scope_drift_applications: driftApps,
      },
      occurrence_breakdown: {
        verified_occurrences: verifiedOccurrences,
        deployed_unverified_occurrences: deployedUnverifiedOccurrences,
        failed_validation_occurrences: failedValidationOccurrences,
        rolled_back_occurrences: rolledBackOccurrences,
        stale_inventory_occurrences: staleInventoryOccurrences,
        unpatched_occurrences: unpatchedOccurrences,
        out_of_scope_unpatched_occurrences: outOfScopeUnpatchedOccurrences,
      },
      planned_benefit_exposures: plannedExposures,
      observed_remediated_exposures: observedRemediated, residual_exposures: residualExposures,
      inventory_or_scope_drift_exposures: driftExposures, non_deployment_signals_ignored: ignoredSignals,
    };
  });

  return {
    schema_version: 'osera-patch-reconciliation-report/v1',
    summary: {
      total_plans: plans.length,
      verified_plan_count: plans.filter(p => p.reconciled_stage === 'verified').length,
      reopened_plan_count: plans.filter(p => p.opportunity_reopened).length,
      planned_benefit_exposure_count: totalPlanned,
      observed_remediated_exposure_count: totalObserved,
      inventory_or_scope_drift_exposure_count: totalDrift,
      residual_exposure_count: plans.reduce((acc, p) => acc + p.residual_exposures.length, 0),
    },
    plans,
  };
}

export function validateAndNormalizeCoverageRequest(rawReq, coReleasedGroupMapping = {}) {
  const rawPurl = String(rawReq.identity || rawReq.purl || '').trim();
  const explicitEco = String(rawReq.ecosystem || '').trim().toLowerCase();
  let eco = '', lib = '', ver = '';

  if (rawPurl.startsWith('pkg:')) {
    const m = /^pkg:([a-z0-9.+-]+)\/([^@#?]+)(?:@([^?#]+))?/i.exec(rawPurl);
    if (!m) throw new Error(`Invalid package URL: ${rawPurl}`);
    eco = m[1].toLowerCase();
    if (!SUPPORTED_ECOSYSTEMS.has(eco)) throw new Error(`Unsupported ecosystem '${eco}'; refusing to silently coerce to Maven.`);
    lib = eco === 'maven' ? m[2].replace('/', ':') : m[2];
    ver = m[3] || '';
  } else {
    if (!explicitEco) throw new Error('Missing explicit ecosystem or PURL; refusing to silently coerce to Maven.');
    if (!SUPPORTED_ECOSYSTEMS.has(explicitEco)) throw new Error(`Unsupported ecosystem '${explicitEco}'; refusing to silently coerce to Maven.`);
    eco = explicitEco;
    lib = String(rawReq.package || rawReq.library || '').trim();
    ver = String(rawReq.version || '').trim();
    if (!lib) throw new Error('Coverage request requires a package coordinate.');
  }

  const precision = String(rawReq.precision || 'exact').toLowerCase();
  if (!['exact', 'minor', 'major'].includes(precision)) throw new Error(`Invalid precision '${precision}'.`);
  const lineVal = String(rawReq.line || '').trim();
  if (!lineVal) throw new Error('Missing line.');
  if (precision === 'exact' && ver && lineVal !== ver) throw new Error('Exact line must match version.');
  if (precision === 'minor' && !/^\d+\.\d+\.x$/.test(lineVal)) throw new Error('Minor line must match N.N.x.');
  if (precision === 'major' && !/^\d+\.x$/.test(lineVal)) throw new Error('Major line must match N.x.');

  const advisories = unique((rawReq.advisories || []).map(a => String(a).trim()));
  if (!advisories.length || advisories.some(a => !ADVISORY_RE.test(a))) throw new Error('Valid CVE/GHSA required.');
  const pkgCoord = `pkg:${eco}/${lib.replace(':', '/')}`;

  return {
    package: pkgCoord,
    ecosystem: eco,
    library: lib,
    scope: { precision, value: lineVal, confirmed_exact_inventory: precision === 'exact' },
    co_release_group: coReleasedGroupMapping[pkgCoord] || coReleasedGroupMapping[lib] || null,
    advisories,
    acceptable_remediation: unique(rawReq.acceptable_remediation || rawReq.remediation || ['backpatch']),
    rationale: String(rawReq.rationale || '').trim() || null,
    incompatibility: String(rawReq.incompatibility || '').trim() || null,
  };
}

export function buildPrivacyPreservingRequestExport(rawRequests, options = {}) {
  const catalog = options.existing_catalog_patches || [];
  const workItems = options.existing_osera_work || [];
  const groupMap = options.co_released_group_mapping || {};

  const merged = new Map();
  for (const raw of rawRequests) {
    const norm = validateAndNormalizeCoverageRequest(raw, groupMap);
    const key = `${norm.package}|${norm.scope.precision}|${norm.scope.value}`;
    const prev = merged.get(key);
    if (!prev) merged.set(key, norm);
    else {
      prev.advisories = unique([...prev.advisories, ...norm.advisories]);
      prev.acceptable_remediation = unique([...prev.acceptable_remediation, ...norm.acceptable_remediation]);
    }
  }

  const requests = [...merged.values()].map(item => {
    const matchingPatches = catalog.filter(p =>
      p.package === item.package &&
      (p.release_state || 'released') === 'released' &&
      item.scope.precision === 'exact' &&
      (p.applicable_versions || []).includes(item.scope.value)
    );
    const covered = new Set(matchingPatches.flatMap(p => p.fixed_advisories || []));
    const unresolved = item.scope.precision === 'exact' ? item.advisories.filter(a => !covered.has(a)) : item.advisories;
    const matchingWork = workItems.filter(w => w.package === item.package && w.line === item.scope.value);
    const lineStatus = item.scope.precision === 'exact' && covered.size && !unresolved.length
      ? 'existing_full_coverage'
      : item.scope.precision === 'exact' && covered.size && unresolved.length
        ? 'supported_line_with_unresolved_new_work'
        : matchingWork.length
          ? 'existing_osera_work_in_progress'
          : (item.scope.precision === 'major' ? 'broad_major_line_review_required' : 'unmet_line_demand');

    return {
      package: item.package,
      ecosystem: item.ecosystem,
      scope: item.scope,
      requested_advisories: item.advisories,
      already_covered_advisories: item.advisories.filter(a => covered.has(a)),
      unresolved_advisories: unresolved,
      acceptable_remediation: item.acceptable_remediation,
      line_coverage_status: lineStatus,
      lifecycle_state: lineStatus === 'existing_full_coverage' ? 'covered' : (matchingWork.length ? 'in_progress' : 'exported'),
      linked_osera_work_urls: matchingWork.map(w => w.url).filter(Boolean),
      linked_released_patches: matchingPatches.map(p => p.replacement_purl || p.target).filter(Boolean),
      counts_as_member_deployment: false,
      ...(item.co_release_group ? { co_release_group: item.co_release_group } : {}),
      ...(item.rationale ? { rationale: item.rationale } : {}),
    };
  });

  const bundle = { schema_version: 'osera-coverage-request/v1', kind: 'osera-coverage-request', submission_status: 'local_export_not_submitted', requests };
  const serialized = JSON.stringify(bundle);
  for (const k of PRIVATE_KEYS) if (serialized.includes(`"${k}"`)) throw new Error(`Privacy leak: ${k}`);
  return bundle;
}

export function deduplicateAuthenticatedIntakeSubmissions(submissions, minKAnonymityMembers = 2) {
  const byLine = new Map();
  for (const sub of submissions) {
    const memberId = String(sub.member_auth_id || '').trim();
    if (!memberId) throw new Error('Missing member_auth_id.');
    const bundle = sub.bundle || sub;
    for (const req of bundle.requests || []) {
      const key = `${req.package}|${req.scope.precision}|${req.scope.value}`;
      if (!byLine.has(key)) {
        byLine.set(key, { package: req.package, scope: req.scope, members: new Set(), attempts: 0, advisories: new Set(), rationales: [] });
      }
      const entry = byLine.get(key);
      entry.attempts += 1;
      entry.members.add(memberId);
      (req.unresolved_advisories || req.requested_advisories || req.advisories || []).forEach(a => entry.advisories.add(a));
      if (req.rationale) entry.rationales.push(req.rationale);
    }
  }
  return {
    schema_version: 'osera-coverage-intake-summary/v1',
    min_k_anonymity_members: minKAnonymityMembers,
    public_lines: [...byLine.values()].map(e => ({
      package: e.package,
      scope: e.scope,
      unique_member_demand_count: e.members.size,
      duplicate_submissions_collapsed: e.attempts - e.members.size,
      advisories: [...e.advisories].sort(),
      rare_request_privacy_redacted: e.members.size < minKAnonymityMembers,
      public_rationale_summary: e.members.size < minKAnonymityMembers ? 'Redacted under rare-request k-anonymity threshold' : (e.rationales[0] || null),
    })),
  };
}
