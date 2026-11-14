#!/usr/bin/env python3
"""Refresh the public FINOS sample; publish only size-checked application artifacts."""
from __future__ import annotations

import argparse
import csv
import json
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

from build_dataset import build_dataset
from extract_org import DepEdge, Project, write_scope_extract, now_iso
from ingest_vulns import file_sha256
from build_package_allowlist import read_dep_edges
from fetch_external import KEV_URL, fetch_json, normalize_kev, fetch_epss
from validate_dataset import validate
from resolve_osv_inventory import resolve_inventory

ROOT = Path(__file__).resolve().parents[1]
SCOPE = "finos-github-org"
LOCAL = ROOT / "data/local/finos-refresh"
MAX_DATASET_BYTES = 5 * 1024 * 1024
MAX_REPORT_BYTES = 256 * 1024


def run(script, *args):
    subprocess.run([sys.executable, str(ROOT / "scripts" / script), *map(str, args)], cwd=ROOT, check=True)


def read_rows(path):
    with path.open(newline="") as handle:
        return list(csv.DictReader(handle))


def compact_dataset(dataset, edges):
    """Keep evidence and every version, but avoid repeating long advisory prose."""
    # Full upstream descriptions remain in the ignored local database. The UI can
    # show a short summary and the authoritative CVE reference for further detail.
    chains = {}
    for lib in dataset["libraries"]:
        key = "|".join([lib["namespace"], lib["meta"], lib["proj"]])
        chain = lib.get("version_chain", [])
        if key in chains and chains[key] != chain:
            raise ValueError(f"Inconsistent version chains for {key}")
        chains[key] = chain
        lib["version_chain"] = []
        lib["version_chain_ref"] = key
        lib["library_itso"] = {"tai_system": "unknown", "primary_owner": "unknown", "department": "Unknown"}
        for cve in lib["cves"]:
            description = cve.get("description", "")
            summary = cve.get("summary") or description
            cve["summary"] = summary[:500] + ("…" if len(summary) > 500 else "")
            cve["description"] = ""
    dataset["version_chains"] = chains
    # Preserve all extracted inventory, including packages without CVEs. Indexed
    # edges prevent repeating long coordinates and repository names thousands of times.
    libraries = sorted({e.library_id for e in edges} | {e.parent_id for e in edges if e.parent_id})
    projects = sorted({e.consumer_id for e in edges})
    lib_index = {value: index for index, value in enumerate(libraries)}
    project_index = {value: index for index, value in enumerate(projects)}
    dataset["dependency_inventory"] = {
        "schema_version": 1,
        "evidence": "Repository declarations and selected npm lockfiles; not deployed estate evidence.",
        "libraries": libraries, "projects": projects,
        "edge_columns": ["project", "library", "direct", "qualifier", "parent"],
        "edges": sorted({(project_index[e.consumer_id], lib_index[e.library_id], e.direct, e.qualifier,
                          lib_index[e.parent_id] if e.parent_id else None) for e in edges}, key=str),
    }
    return dataset


def publish(dataset, report):
    staging = LOCAL / "publish"
    staging.mkdir(parents=True, exist_ok=True)
    dataset_path = staging / f"{SCOPE}.json"
    report_path = staging / "finos-coverage.json"
    dataset_path.write_text(json.dumps(dataset, separators=(",", ":")) + "\n")
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    for path, limit in [(dataset_path, MAX_DATASET_BYTES), (report_path, MAX_REPORT_BYTES)]:
        if path.stat().st_size > limit:
            raise RuntimeError(f"Refusing to publish {path.name}: {path.stat().st_size:,} bytes exceeds {limit:,}; staged output stays local")
    errors = validate(dataset_path)
    if errors:
        raise RuntimeError("; ".join(errors))
    if report["repositories_failed"]:
        raise RuntimeError("Repository scans failed; inspect local coverage report before publishing")
    for path in [dataset_path, report_path]:
        shutil.copyfile(path, ROOT / "data" / path.name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reuse-inventory", action="store_true", help="Resume from local scan evidence; retains original scan timestamps")
    parser.add_argument("--reuse-vulnerabilities", action="store_true", help="Resume from local OSV DB (manual recovery only)")
    args = parser.parse_args()
    LOCAL.mkdir(parents=True, exist_ok=True)
    raw_root = LOCAL / "raw"
    raw = raw_root / SCOPE
    db = LOCAL / "vulns.db"
    if not args.reuse_inventory:
        run("extract_org.py", "--scope", SCOPE, "--source", "finos-github", "--raw-root", raw_root,
            "--db", LOCAL / "empty.db", "--github-max-manifests-per-repo", 32, "--github-parallelism", 12)
    coverage = json.loads((raw / "coverage.json").read_text())
    if any(row["status"] == "failed" for row in coverage):
        raise RuntimeError("Repository scan failures; refusing to replace the published snapshot")
    if not args.reuse_vulnerabilities:
        run("fetch_osv_source.py")
        osv_meta = json.loads((ROOT / "data/local/osv/all.zip.meta.json").read_text())
        if max(osv_meta.get("fetched_at", ""), osv_meta.get("checked_at", ""))[:10] != now_iso()[:10]:
            raise RuntimeError("OSV freshness check failed; refusing stale fallback")
        run("build_package_allowlist.py", "--scope", SCOPE, "--raw-root", raw_root)
        run("ingest_vulns.py", "--source-zip", ROOT / "data/local/osv/all.zip", "--source-dir", LOCAL / "osv-empty",
            "--db", db, "--package-allowlist-file", ROOT / f"data/local/allowlists/{SCOPE}-packages.txt")
    ingest_meta = json.loads(db.with_suffix(".db.meta.json").read_text())
    if args.reuse_vulnerabilities:
        fingerprint = ingest_meta["fingerprint"]
        if file_sha256(ROOT / "data/local/osv/all.zip") != fingerprint["source_zip_sha256"]:
            raise RuntimeError("Local OSV archive changed; rerun without --reuse-vulnerabilities")
        allowlist = ROOT / f"data/local/allowlists/{SCOPE}-packages.txt"
        expected_keys = {tuple(line.split("|")) for line in allowlist.read_text().splitlines() if line and not line.startswith("#")}
        if read_dep_edges(raw / "02-dep-edges.csv") != expected_keys or file_sha256(allowlist) != fingerprint["package_allowlist_sha256"]:
            raise RuntimeError("Inventory packages changed; rerun without --reuse-vulnerabilities")
    projects = [Project(**row) for row in read_rows(raw / "01-consumer-projects.csv")]
    edges = [DepEdge(**{**row, "direct": int(row["direct"])}) for row in read_rows(raw / "02-dep-edges.csv")]
    exact_version_stats = resolve_inventory(db, edges, LOCAL)
    write_scope_extract(SCOPE, projects, edges, db, raw_root)
    cves = sorted({row["cve_id"] for row in read_rows(raw / "06-cve-edges.csv")})
    external = LOCAL / "external"
    external.mkdir(exist_ok=True)
    # Fail closed: a real snapshot must never silently fall back to demo signals.
    print(f"Refreshing KEV and EPSS for {len(cves)} observed CVEs", flush=True)
    kev = normalize_kev(fetch_json(KEV_URL))
    epss = fetch_epss(cves)
    for name, payload in [("kev", kev), ("epss", epss)]:
        (external / f"{name}.json").write_text(json.dumps(payload))
    overlay = json.loads((ROOT / f"data/meta/{SCOPE}-meta.json").read_text())
    overlay["dataset_methodology"] = {
        "summary": "Live FINOS public non-fork active repository manifests, with selected npm v2/v3 runtime lockfile graphs.",
        "build_command": "npm run refresh:finos",
        "limitations": [
            "Declared manifest ranges are approximated by the existing parser; only lockfile entries represent resolved versions.",
            "No repository builds are executed. Maven/Gradle inheritance, Yarn/pnpm/Python lockfiles and container contents are not fully resolved.",
            "32 manifests per repository and 4 lockfiles per selected repository; coverage report records truncation and failures.",
            "Repository evidence is not proof of deployed versions or patch adoption. Unscanned dependencies are unknown, not clean.",
            "Advisory descriptions are shortened for distribution; full descriptions remain in local OSV data.",
        ],
    }
    if not args.reuse_inventory:
        (LOCAL / "depsdev.json").unlink(missing_ok=True)
    dataset = build_dataset(SCOPE, raw_root, external, LOCAL / "build", db,
                            depsdev_cache_path=LOCAL / "depsdev.json", cve_metadata_cache_path=LOCAL / "cve-metadata.json",
                            osv_source_dir=LOCAL / "osv-empty", enrich_cve_metadata_online=False, meta_overlay=overlay)
    report = {
        "generated_at": now_iso(), "inventory_started_at": min(r["scanned_at"] for r in coverage),
        "inventory_completed_at": max(r["scanned_at"] for r in coverage),
        "repositories": len(coverage), "repositories_with_dependencies": sum(bool(r.get("dependency_edges")) for r in coverage),
        "repositories_failed": sum(r["status"] == "failed" for r in coverage),
        "status_counts": dict(Counter(r["status"] for r in coverage)),
        "dependency_edges": len(edges), "resolved_lockfiles": sum(len(r.get("lockfiles", [])) for r in coverage),
        "distinct_package_versions": len({e.library_id for e in edges}),
        "runtime_transitive_edges": sum(not e.direct and e.qualifier == "runtime" for e in edges),
        "vulnerable_library_versions": len(dataset["libraries"]),
        "unique_cves": len({c["cve_id"] for lib in dataset["libraries"] for c in lib["cves"]}),
        "sources": {"osv_exact_versions": exact_version_stats, "osv_ingested_at": ingest_meta["updated_at"], "osv_sha256": ingest_meta["fingerprint"]["source_zip_sha256"], "osv": json.loads((ROOT / "data/local/osv/all.zip.meta.json").read_text()),
                    "kev_fetched_at": kev["fetched_at"], "epss_fetched_at": epss["fetched_at"]},
        "repository_details": coverage,
    }
    dataset["meta"]["inventory_scanned_at"] = report["inventory_completed_at"]
    dataset["meta"]["coverage"] = {k: v for k, v in report.items() if k not in ("repository_details", "sources")}
    dataset["meta"]["vulnerabilities_queried_at"] = exact_version_stats["queried_at"]
    dataset["meta"]["vulnerabilities_fetched_at"] = report["sources"]["osv"].get("fetched_at")
    publish(compact_dataset(dataset, edges), report)
    manifest_path = ROOT / "tool/manifest.json"
    manifest = json.loads(manifest_path.read_text())
    entry = next(e for e in manifest["datasets"] if e["url"] == f"../data/{SCOPE}.json")
    entry.update({
        "source_type": "public-github-manifests-and-lockfiles",
        "description": "Current public FINOS repository declarations with selected resolved npm runtime dependency graphs.",
        "coverage": f"{report['repositories']} repositories; {report['repositories_with_dependencies']} with dependencies; {report['resolved_lockfiles']} resolved lockfiles. Scanned {report['inventory_completed_at'][:10]}.",
        "limitations": "Partial repository evidence, not deployed inventory. Scan limits and unsupported formats are listed in the coverage report; curated demos remain separate.",
    })
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k not in ("repository_details", "sources")}, indent=2))


if __name__ == "__main__":
    main()
