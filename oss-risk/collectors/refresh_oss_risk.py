#!/usr/bin/env python3
"""Refresh and validate OSS-risk datasets; publish only validated artifacts (#70)."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

COLLECTORS_DIR = Path(__file__).resolve().parent
ROOT = COLLECTORS_DIR.parent.parent
if str(COLLECTORS_DIR) not in sys.path:
    sys.path.insert(0, str(COLLECTORS_DIR))

import collect_oss_risk as collector  # noqa: E402
import discover_finos_osera_backpatch as discovery  # noqa: E402

DATA_DIR = ROOT / "oss-risk" / "data"
DEFAULT_BACKPATCH_SEEDS = DATA_DIR / "finos-osera-backpatch-libraries.json"
DEFAULT_BACKPATCH_SCORECARDS = DATA_DIR / "finos-osera-backpatch-scorecards.json"
DEFAULT_EXAMPLE_SEEDS = collector.DEFAULT_INPUT
DEFAULT_EXAMPLE_SCORECARDS = DATA_DIR / "collected-library-scorecards.json"
DEFAULT_STAGING_DIR = ROOT / "data" / "local" / "oss-risk-refresh" / "publish"
MAX_DATASET_BYTES = 5 * 1024 * 1024
MIN_BACKPATCH_RECORDS = 50
MIN_EXAMPLE_RECORDS = 5


def validate_seed_payload(
    payload: Dict[str, Any],
    *,
    min_records: int = MIN_BACKPATCH_RECORDS,
    label: str = "finos-osera-backpatch-libraries.json",
) -> List[str]:
    errors: List[str] = []
    if not isinstance(payload, dict):
        return [f"{label}: root payload must be a JSON object"]
    records = payload.get("records")
    if not isinstance(records, list):
        return [f"{label}: 'records' must be a list"]
    if len(records) < min_records:
        errors.append(
            f"{label}: expected at least {min_records} seed records, found {len(records)}"
        )
    seen_names: set[str] = set()
    for idx, rec in enumerate(records):
        if not isinstance(rec, dict):
            errors.append(f"{label}[{idx}]: record must be an object")
            continue
        proj = rec.get("project")
        if not isinstance(proj, dict):
            errors.append(f"{label}[{idx}]: missing 'project' object")
            continue
        name = str(proj.get("name") or "").strip()
        ecosystem = str(proj.get("ecosystem") or "").strip()
        package = str(proj.get("package") or "").strip()
        if not name or not ecosystem or not package:
            errors.append(
                f"{label}[{idx}]: project requires non-empty name, ecosystem, and package"
            )
        if name in seen_names:
            errors.append(f"{label}[{idx}]: duplicate project name {name!r}")
        seen_names.add(name)
    return errors


def validate_scorecards_payload(
    payload: Dict[str, Any],
    *,
    min_records: int = 1,
    require_covered_openvex: bool = False,
    label: str = "scorecards.json",
) -> List[str]:
    errors: List[str] = []
    if not isinstance(payload, dict):
        return [f"{label}: root payload must be a JSON object"]
    if payload.get("schema_version") != "0.1":
        errors.append(
            f"{label}: expected schema_version '0.1', got {payload.get('schema_version')!r}"
        )
    generated_at = str(payload.get("generated_at") or "").strip()
    if not generated_at:
        errors.append(f"{label}: missing top-level 'generated_at' timestamp")
    records = payload.get("records")
    if not isinstance(records, list):
        return errors + [f"{label}: 'records' must be a list"]
    if len(records) < min_records:
        errors.append(
            f"{label}: expected at least {min_records} records, found {len(records)}"
        )

    covered_openvex_count = 0
    github_success_count = 0
    github_configured_count = 0

    for idx, rec in enumerate(records):
        if not isinstance(rec, dict):
            errors.append(f"{label}[{idx}]: record must be an object")
            continue
        proj = rec.get("project") or {}
        pkg_label = f"{proj.get('ecosystem', '?')}:{proj.get('package', idx)}"
        scores = rec.get("scores")
        evidence = rec.get("evidence")
        if not isinstance(scores, dict) or "oss_vitality" not in scores:
            errors.append(f"{label} ({pkg_label}): missing scores.oss_vitality")
        if not isinstance(evidence, dict):
            errors.append(f"{label} ({pkg_label}): missing evidence object")
            continue

        # 1. Validate OSERA OpenVEX evidence provenance and availability
        openvex = evidence.get("osera_openvex")
        if not isinstance(openvex, dict):
            errors.append(f"{label} ({pkg_label}): missing evidence.osera_openvex")
        else:
            cov_status = openvex.get("coverage_status")
            openvex_api_err = (openvex.get("api") or {}).get("error") if isinstance(openvex.get("api"), dict) else None
            if cov_status == "unavailable" or openvex.get("error") or openvex_api_err:
                errors.append(
                    f"{label} ({pkg_label}): OSERA OpenVEX feed unavailable ({openvex.get('error') or openvex_api_err or cov_status})"
                )
            elif cov_status not in {"covered", "no_published_osera_fix", "not_applicable", "not-applicable"}:
                errors.append(
                    f"{label} ({pkg_label}): unexpected osera_openvex.coverage_status {cov_status!r}"
                )
            if cov_status in {"covered", "no_published_osera_fix"}:
                if not openvex.get("retrieved_at"):
                    errors.append(
                        f"{label} ({pkg_label}): osera_openvex missing retrieved_at timestamp"
                    )
                if openvex.get("feed_version") is None:
                    errors.append(
                        f"{label} ({pkg_label}): osera_openvex missing feed_version"
                    )
            if cov_status == "covered":
                covered_openvex_count += 1

        # 2. Validate OSV and CISA KEV evidence when applicable
        osv = evidence.get("osv")
        if not isinstance(osv, dict):
            errors.append(f"{label} ({pkg_label}): missing evidence.osv")
        else:
            osv_source = osv.get("source")
            osv_api_err = (osv.get("api") or {}).get("error") if isinstance(osv.get("api"), dict) else None
            if osv_source in {"osv-query-api", "osv.dev"}:
                if osv.get("error") or osv_api_err:
                    errors.append(
                        f"{label} ({pkg_label}): OSV query failed: {osv.get('error') or osv_api_err}"
                    )
                if not osv.get("observed_at"):
                    errors.append(f"{label} ({pkg_label}): OSV missing observed_at")
                kev = evidence.get("cisa_kev")
                kev_api_err = (kev.get("api") or {}).get("error") if isinstance(kev, dict) and isinstance(kev.get("api"), dict) else None
                if not isinstance(kev, dict) or kev.get("source") not in {"cisa-kev-json", "cisa-kev"}:
                    errors.append(
                        f"{label} ({pkg_label}): missing CISA KEV evidence for applicable OSV record"
                    )
                elif kev.get("error") or kev_api_err:
                    errors.append(
                        f"{label} ({pkg_label}): CISA KEV feed failed: {kev.get('error') or kev_api_err}"
                    )
                elif not (kev.get("observed_at") or kev.get("retrieved_at")):
                    errors.append(
                        f"{label} ({pkg_label}): CISA KEV missing observed_at/retrieved_at timestamp"
                    )
                elif not kev.get("catalog_count"):
                    errors.append(
                        f"{label} ({pkg_label}): CISA KEV catalog_count is empty"
                    )

        # 3. Validate GitHub evidence and detect API rate-limit / auth / subrequest failures
        repo_url = str(proj.get("repository") or proj.get("repo_url") or "")
        gh = evidence.get("github")
        if "github.com/" in repo_url:
            github_configured_count += 1
            if not isinstance(gh, dict):
                errors.append(f"{label} ({pkg_label}): missing evidence.github")
            else:
                repo_api = gh.get("repo_api")
                gh_repo_err = repo_api.get("error") if isinstance(repo_api, dict) else None
                gh_err = str(gh.get("error") or gh_repo_err or "").strip()
                subrequest_failed = False

                if gh_err:
                    if gh_err != "HTTP 404":
                        errors.append(
                            f"{label} ({pkg_label}): GitHub API error for {repo_url}: {gh_err}"
                        )
                    for sub_key in ("release_api", "tag_api", "commit_api", "issue_api", "pull_api"):
                        sub_meta = gh.get(sub_key)
                        sub_err = str(sub_meta.get("error") or "").strip() if isinstance(sub_meta, dict) else ""
                        if sub_err and sub_err != "HTTP 404":
                            subrequest_failed = True
                            errors.append(
                                f"{label} ({pkg_label}): GitHub subrequest {sub_key} failed for {repo_url}: {sub_err}"
                            )
                else:
                    if not isinstance(repo_api, dict) or not repo_api:
                        subrequest_failed = True
                        errors.append(
                            f"{label} ({pkg_label}): missing github.repo_api metadata for {repo_url}"
                        )
                    for sub_key in ("release_api", "commit_api", "issue_api", "pull_api"):
                        sub_meta = gh.get(sub_key)
                        if not isinstance(sub_meta, dict) or not sub_meta:
                            subrequest_failed = True
                            errors.append(
                                f"{label} ({pkg_label}): missing github.{sub_key} metadata for {repo_url}"
                            )
                        else:
                            sub_err = str(sub_meta.get("error") or "").strip()
                            page_errs = sub_meta.get("page_errors")
                            if not sub_err and isinstance(page_errs, list) and page_errs:
                                first_pe = page_errs[0]
                                sub_err = str(first_pe.get("error") if isinstance(first_pe, dict) else first_pe or "").strip()
                            if sub_err:
                                subrequest_failed = True
                                errors.append(
                                    f"{label} ({pkg_label}): GitHub subrequest {sub_key} failed for {repo_url}: {sub_err}"
                                )
                    tag_meta = gh.get("tag_api")
                    if isinstance(tag_meta, dict) and tag_meta:
                        tag_err = str(tag_meta.get("error") or "").strip()
                        if tag_err:
                            subrequest_failed = True
                            errors.append(
                                f"{label} ({pkg_label}): GitHub subrequest tag_api failed for {repo_url}: {tag_err}"
                            )

                if (
                    not gh_err
                    and not subrequest_failed
                    and gh.get("source") == "github-api"
                    and gh.get("observed_at")
                    and float(gh.get("confidence") or 0) >= 0.8
                ):
                    github_success_count += 1

    if require_covered_openvex and covered_openvex_count == 0:
        errors.append(
            f"{label}: expected at least 1 record with osera_openvex.coverage_status == 'covered', found 0"
        )
    if github_configured_count > 0:
        min_gh_success = max(1, int(github_configured_count * 0.9))
        if github_success_count < min_gh_success:
            errors.append(
                f"{label}: only {github_success_count}/{github_configured_count} GitHub repository lookups succeeded (minimum {min_gh_success})"
            )
    return errors


def check_file_size(path: Path, max_bytes: int = MAX_DATASET_BYTES) -> Optional[str]:
    size = path.stat().st_size
    if size > max_bytes:
        return f"{path.name}: file size {size:,} bytes exceeds limit {max_bytes:,} bytes"
    return None


def validate_existing_files(
    *,
    backpatch_seeds_path: Path = DEFAULT_BACKPATCH_SEEDS,
    backpatch_scorecards_path: Path = DEFAULT_BACKPATCH_SCORECARDS,
    example_scorecards_path: Path = DEFAULT_EXAMPLE_SCORECARDS,
) -> List[str]:
    errors: List[str] = []
    for path in (backpatch_seeds_path, backpatch_scorecards_path, example_scorecards_path):
        if not path.exists():
            errors.append(f"Missing required OSS-risk dataset file: {path}")
            continue
        size_err = check_file_size(path)
        if size_err:
            errors.append(size_err)
    if errors:
        return errors

    seeds_payload = json.loads(backpatch_seeds_path.read_text(encoding="utf-8"))
    bp_payload = json.loads(backpatch_scorecards_path.read_text(encoding="utf-8"))
    ex_payload = json.loads(example_scorecards_path.read_text(encoding="utf-8"))

    errors.extend(
        validate_seed_payload(
            seeds_payload,
            min_records=MIN_BACKPATCH_RECORDS,
            label=backpatch_seeds_path.name,
        )
    )
    errors.extend(
        validate_scorecards_payload(
            bp_payload,
            min_records=MIN_BACKPATCH_RECORDS,
            require_covered_openvex=True,
            label=backpatch_scorecards_path.name,
        )
    )
    errors.extend(
        validate_scorecards_payload(
            ex_payload,
            min_records=MIN_EXAMPLE_RECORDS,
            require_covered_openvex=False,
            label=example_scorecards_path.name,
        )
    )
    return errors


def run_refresh(
    *,
    staging_dir: Path = DEFAULT_STAGING_DIR,
    output_dir: Path = DATA_DIR,
    cache_dir: Path = collector.DEFAULT_CACHE,
    example_seeds_path: Path = DEFAULT_EXAMPLE_SEEDS,
    skip_discovery: bool = False,
    require_live_discovery: bool = False,
    skip_examples: bool = False,
    reuse_cache: bool = False,
    allow_unauthenticated_github: bool = False,
    allow_shrink: bool = False,
    min_backpatch_records: int = MIN_BACKPATCH_RECORDS,
    min_example_records: int = MIN_EXAMPLE_RECORDS,
) -> Dict[str, Path]:
    token = discovery.github_token()
    if not token and not allow_unauthenticated_github:
        raise RuntimeError(
            "GitHub API authentication is required for full OSS-risk refresh "
            "(set GITHUB_TOKEN or GH_TOKEN, or pass --allow-unauthenticated-github)."
        )

    staging_dir.mkdir(parents=True, exist_ok=True)
    staged_seeds = staging_dir / DEFAULT_BACKPATCH_SEEDS.name
    staged_bp = staging_dir / DEFAULT_BACKPATCH_SCORECARDS.name
    staged_ex = staging_dir / DEFAULT_EXAMPLE_SCORECARDS.name

    # 1. Discover or copy FINOS OSERA backpatch seed records into staging
    source_seeds = output_dir / DEFAULT_BACKPATCH_SEEDS.name
    if not source_seeds.exists():
        source_seeds = DEFAULT_BACKPATCH_SEEDS

    if skip_discovery:
        shutil.copyfile(source_seeds, staged_seeds)
        seeds_payload = json.loads(staged_seeds.read_text(encoding="utf-8"))
    else:
        gh_client = discovery.GitHubClient()
        observed_at = discovery.now_iso()
        repos = [
            r
            for r in discovery.list_org_repos(gh_client, discovery.ORG)
            if isinstance(r.get("name"), str)
            and r["name"].startswith(discovery.PREFIX)
            and not r.get("archived")
        ]
        if not repos and not require_live_discovery and source_seeds.exists():
            shutil.copyfile(source_seeds, staged_seeds)
            seeds_payload = json.loads(staged_seeds.read_text(encoding="utf-8"))
            print(
                f"Note: /orgs/{discovery.ORG}/repos returned 0 visible {discovery.PREFIX}* repositories "
                f"with the current token; retaining existing seed inventory "
                f"(generated_at={seeds_payload.get('generated_at')}) and refreshing live scorecard evidence.",
                file=sys.stderr,
            )
        else:
            seed_records = []
            skipped = []
            for repo in sorted(repos, key=lambda item: item["name"]):
                rec = discovery.make_record(gh_client, repo, observed_at)
                if rec:
                    seed_records.append(rec)
                else:
                    skipped.append(repo.get("full_name") or repo["name"])
            seeds_payload = {
                "schema_version": "0.1",
                "generated_at": observed_at,
                "source": f"github-org:{discovery.ORG}",
                "repository_prefix": discovery.PREFIX,
                "records": seed_records,
                "skipped": skipped,
            }
            staged_seeds.write_text(json.dumps(seeds_payload, indent=2) + "\n", encoding="utf-8")

    seed_errors = validate_seed_payload(
        seeds_payload,
        min_records=min_backpatch_records,
        label=staged_seeds.name,
    )
    seed_size_err = check_file_size(staged_seeds)
    if seed_size_err:
        seed_errors.append(seed_size_err)
    if seed_errors:
        raise RuntimeError(
            "Refusing to continue refresh due to invalid seed discovery:\n- "
            + "\n- ".join(seed_errors)
        )

    # Check against baseline shrink on existing backpatch scorecards
    existing_bp_path = output_dir / DEFAULT_BACKPATCH_SCORECARDS.name
    if existing_bp_path.exists() and not allow_shrink:
        try:
            existing_bp = json.loads(existing_bp_path.read_text(encoding="utf-8"))
            existing_count = len(existing_bp.get("records") or [])
            if len(seeds_payload.get("records") or []) < existing_count:
                raise RuntimeError(
                    f"Discovered seed count ({len(seeds_payload.get('records') or [])}) is smaller than "
                    f"existing published snapshot ({existing_count}); pass --allow-shrink if intentional."
                )
        except json.JSONDecodeError:
            pass

    # 2. Collect live evidence with explicit cache refresh
    observed = datetime.now(timezone.utc).replace(microsecond=0)
    http_client = collector.HttpClient(cache_dir, refresh=not reuse_cache)

    bp_records = [
        collector.collect_record(http_client, rec, observed, include_osv=True)
        for rec in seeds_payload["records"]
    ]
    bp_payload = {
        "schema_version": "0.1",
        "generated_at": observed.isoformat().replace("+00:00", "Z"),
        "methodology": "Live public API evidence collection plus v0 deterministic scoring heuristics.",
        "records": bp_records,
    }
    staged_bp.write_text(json.dumps(bp_payload, indent=2) + "\n", encoding="utf-8")

    validation_errors: List[str] = []
    staged_seed_size_err = check_file_size(staged_seeds)
    if staged_seed_size_err:
        validation_errors.append(staged_seed_size_err)
    validation_errors.extend(
        validate_scorecards_payload(
            bp_payload,
            min_records=min_backpatch_records,
            require_covered_openvex=True,
            label=staged_bp.name,
        )
    )
    size_err = check_file_size(staged_bp)
    if size_err:
        validation_errors.append(size_err)

    staged_files: List[tuple[Path, Path]] = [
        (staged_seeds, output_dir / DEFAULT_BACKPATCH_SEEDS.name),
        (staged_bp, output_dir / DEFAULT_BACKPATCH_SCORECARDS.name),
    ]

    if not skip_examples:
        example_seeds = collector.read_records(example_seeds_path)
        ex_records = [
            collector.collect_record(http_client, rec, observed, include_osv=True)
            for rec in example_seeds
        ]
        ex_payload = {
            "schema_version": "0.1",
            "generated_at": observed.isoformat().replace("+00:00", "Z"),
            "methodology": "Live public API evidence collection plus v0 deterministic scoring heuristics.",
            "records": ex_records,
        }
        staged_ex.write_text(json.dumps(ex_payload, indent=2) + "\n", encoding="utf-8")
        validation_errors.extend(
            validate_scorecards_payload(
                ex_payload,
                min_records=min_example_records,
                require_covered_openvex=False,
                label=staged_ex.name,
            )
        )
        ex_size_err = check_file_size(staged_ex)
        if ex_size_err:
            validation_errors.append(ex_size_err)
        staged_files.append((staged_ex, output_dir / DEFAULT_EXAMPLE_SCORECARDS.name))

    if validation_errors:
        raise RuntimeError(
            "Refusing to publish refreshed OSS-risk dataset; staged output failed validation:\n- "
            + "\n- ".join(validation_errors)
        )

    return publish_dataset_set(staged_files)


def _write_bytes_fsync(path: Path, data: bytes) -> None:
    with open(path, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())


def _commit_staged_file(tmp_path: Path, dst: Path) -> None:
    os.replace(tmp_path, dst)


def publish_dataset_set(staged_files: Sequence[tuple[Path, Path]]) -> Dict[str, Path]:
    """Transactionally publish all staged dataset files or roll back the entire set on error."""
    if not staged_files:
        return {}
    pid = os.getpid()
    had_original: Dict[Path, bool] = {}
    backups: Dict[Path, Path] = {}
    temps: Dict[Path, Path] = {}

    for _, dst in staged_files:
        dst.parent.mkdir(parents=True, exist_ok=True)
        existed = dst.exists()
        had_original[dst] = existed
        if existed:
            bak_path = dst.parent / f".{dst.name}.bak.{pid}"
            _write_bytes_fsync(bak_path, dst.read_bytes())
            backups[dst] = bak_path

    published: Dict[str, Path] = {}
    try:
        # Phase 1: Copy all staged files to sibling .tmp files on the destination filesystem and fsync
        for src, dst in staged_files:
            tmp_path = dst.parent / f".{dst.name}.tmp.{pid}"
            temps[dst] = tmp_path
            shutil.copyfile(src, tmp_path)
            with open(tmp_path, "rb") as fh:
                os.fsync(fh.fileno())

        # Phase 2: Atomically replace each destination file; if any step fails, except block restores all
        for _, dst in staged_files:
            _commit_staged_file(temps[dst], dst)
            published[dst.name] = dst
    except BaseException:
        for _, dst in staged_files:
            if had_original.get(dst):
                bak_path = backups.get(dst)
                if bak_path is not None and bak_path.exists():
                    os.replace(bak_path, dst)
            elif dst.exists():
                dst.unlink()
        raise
    finally:
        for path in [*temps.values(), *backups.values()]:
            if path.exists():
                try:
                    path.unlink()
                except OSError:
                    pass

    return published


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Validate existing published OSS-risk JSON datasets without running live collection.",
    )
    parser.add_argument(
        "--staging-dir",
        type=Path,
        default=DEFAULT_STAGING_DIR,
        help="Directory for staging and validating refreshed JSON before atomic publication.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DATA_DIR,
        help="Target directory for published OSS-risk JSON files.",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=collector.DEFAULT_CACHE,
        help="HTTP response cache directory.",
    )
    parser.add_argument(
        "--skip-discovery",
        action="store_true",
        help="Reuse existing finos-osera-backpatch-libraries.json seed file instead of querying GitHub org repos.",
    )
    parser.add_argument(
        "--require-live-discovery",
        action="store_true",
        help="Fail closed if /orgs/finos-osera/repos returns 0 visible backpatch-* repositories instead of retaining the committed seed inventory.",
    )
    parser.add_argument(
        "--skip-examples",
        action="store_true",
        help="Skip refreshing collected-library-scorecards.json.",
    )
    parser.add_argument(
        "--reuse-cache",
        action="store_true",
        help="Allow reusing cached HTTP responses (local debugging only; default refreshes all live sources).",
    )
    parser.add_argument(
        "--allow-unauthenticated-github",
        action="store_true",
        help="Allow running without GITHUB_TOKEN / GH_TOKEN (for mocked/offline tests only).",
    )
    parser.add_argument(
        "--allow-shrink",
        action="store_true",
        help="Allow publishing when discovered backpatch seed count is smaller than the current snapshot.",
    )
    parser.add_argument(
        "--min-backpatch-records",
        type=int,
        default=MIN_BACKPATCH_RECORDS,
        help="Minimum required record count for the FINOS OSERA backpatch dataset.",
    )
    parser.add_argument(
        "--min-example-records",
        type=int,
        default=MIN_EXAMPLE_RECORDS,
        help="Minimum required record count for the general example dataset.",
    )
    args = parser.parse_args(argv)

    if args.validate_only:
        errors = validate_existing_files(
            backpatch_seeds_path=args.output_dir / DEFAULT_BACKPATCH_SEEDS.name,
            backpatch_scorecards_path=args.output_dir / DEFAULT_BACKPATCH_SCORECARDS.name,
            example_scorecards_path=args.output_dir / DEFAULT_EXAMPLE_SCORECARDS.name,
        )
        if errors:
            for err in errors:
                print(f"error: {err}", file=sys.stderr)
            return 1
        print("OSS-risk dataset validation passed")
        return 0

    try:
        published = run_refresh(
            staging_dir=args.staging_dir,
            output_dir=args.output_dir,
            cache_dir=args.cache_dir,
            skip_discovery=args.skip_discovery,
            require_live_discovery=args.require_live_discovery,
            skip_examples=args.skip_examples,
            reuse_cache=args.reuse_cache,
            allow_unauthenticated_github=args.allow_unauthenticated_github,
            allow_shrink=args.allow_shrink,
            min_backpatch_records=args.min_backpatch_records,
            min_example_records=args.min_example_records,
        )
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    for name, path in published.items():
        print(f"Published validated {name} -> {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
