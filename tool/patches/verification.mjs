// Track patch plans through deployment and verify realized remediation (#28), and export/deduplicate private estate coverage requests (#29, #42).
import { purl, unique } from './catalog.mjs';

const SUPPORTED_ECOSYSTEMS = new Set(['maven', 'npm', 'pypi', 'golang', 'nuget', 'cargo', 'composer', 'gem']);
const ADVISORY_RE = /^(?:CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})$/i;
const PRIVATE_KEYS = new Set([
  'application_id', 'applications', 'affected_applications', 'consumer_project_ids',
  'direct_consumer_project_ids', 'owner', 'owners', 'dependency_path', 'dependency_paths',
  'contract_id', 'pricing', 'internal_repository_url', 'scope_name',
]);

export function reconcilePatchPlansWithObservations(bundle) {
  const staleCutoff = String(bundle.stale_inventory_cutoff || '2026-10-20T00:00:00Z');
  const withdrawnPurls = new Set(bundle.withdrawn_artifacts || []);
  const invalidatedAdvisories = new Set(bundle.invalidated_advisory_claims || []);
  const obsByApp = new Map((bundle.deployment_observations || []).map(o => [o.application_id, o]));

  let totalPlanned = 0, totalObserved = 0, totalDrift = 0;

  const plans = (bundle.plans || []).map(plan => {
    const planId = String(plan.plan_id || 'plan');
    const oppId = String(plan.opportunity_id || planId);
    const priorStage = String(plan.current_stage || 'planned').toLowerCase();
    const selectedPurl = String(plan.selected_artifact_purl || '');
    const selectedDigest = plan.selected_artifact_digest || null;
    const sourcePurl = String(plan.source_artifact_purl || '');
    const requiredEnv = String(plan.required_environment || 'production').toLowerCase();
    const targetApps = plan.target_applications || [];
    const expectedAdvs = plan.expected_fixed_advisories || [];
    const plannedExposures = targetApps.flatMap(app => expectedAdvs.map(adv => `${app}|${adv}`));
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
    for (const app of targetApps) {
      const obs = obsByApp.get(app);
      if (!obs || obs.removed_from_scope === true) { driftApps.push(app); continue; }
      const isStale = Boolean(obs.observed_at && obs.observed_at < staleCutoff);
      if (isStale) staleApps.push(app);
      const matches = obs.observed_purl === selectedPurl &&
        String(obs.environment || 'production').toLowerCase() === requiredEnv &&
        (!selectedDigest || obs.observed_artifact_digest === selectedDigest);
      if (matches) {
        if (obs.validation_status === 'failed') failedValidation.push(app);
        else if (obs.validation_status === 'passed' && !isStale) verifiedApps.push(app);
        else deployedUnverified.push(app);
      } else if ((obs.previously_deployed_target || priorStage === 'verified') && obs.observed_purl === sourcePurl) {
        rolledBack.push(app);
      } else {
        unpatched.push(app);
      }
    }

    const observedRemediated = verifiedApps.flatMap(app => expectedAdvs.filter(a => !invalidatedAdvisories.has(a)).map(a => `${app}|${a}`));
    const driftExposures = driftApps.flatMap(app => expectedAdvs.map(a => `${app}|${a}`));
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
    } else if (verifiedApps.length || deployedUnverified.length) {
      reconciledStage = (staleApps.length || (verifiedApps.length + deployedUnverified.length < targetApps.length - driftApps.length))
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
      reopened_reason: reopenedReason, planned_benefit_exposures: plannedExposures,
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
