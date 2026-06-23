#!/usr/bin/env python3
"""Clone selected public repositories and generate CycloneDX SBOMs.

This is an optional demo-data helper. It intentionally writes cloned repos under
data/local/ so generated worktrees stay local-only, while SBOM JSON can be kept
or committed as reproducible demo input.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from extract_org import DEFAULT_GITHUB_API, get_github_token, list_org_repositories

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SCOPE = "finos-sbom-demo"
DEFAULT_REPOS = [
    "legend-studio",
    "perspective",
    "symphony-bdk-java",
    "open-regtech",
    "fdb-record-layer",
]


def run(cmd: Sequence[str], cwd: Optional[Path] = None) -> None:
    subprocess.run(list(cmd), cwd=str(cwd) if cwd else None, check=True)


def selected_repo_names(args: argparse.Namespace) -> List[str]:
    if args.repos:
        return [repo.strip() for repo in args.repos.split(",") if repo.strip()]
    if args.default_demo_repos:
        return list(DEFAULT_REPOS)

    token = get_github_token(str(args.github_token or "").strip() or None)
    rows = list_org_repositories(
        org=args.org,
        token=token,
        github_api_base=str(args.github_api_base).rstrip("/"),
        timeout_seconds=max(5, int(args.github_timeout_seconds)),
        include_archived=bool(args.github_include_archived),
        max_repos=max(0, int(args.max_repos or 0)),
    )
    return [str(row.get("name") or "") for row in rows if str(row.get("name") or "").strip()]


def ensure_scanner(scanner: str) -> str:
    binary = shutil.which(scanner)
    if not binary:
        raise SystemExit(
            f"{scanner!r} was not found on PATH. Install cdxgen or syft, "
            "or commit pre-generated CycloneDX SBOMs under data/sboms/<scope>/."
        )
    return binary


def clone_or_update(repo_url: str, dest: Path, force: bool) -> None:
    if dest.exists() and force:
        shutil.rmtree(dest)
    if dest.exists():
        run(["git", "fetch", "--depth", "1", "origin"], cwd=dest)
        run(["git", "checkout", "FETCH_HEAD"], cwd=dest)
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    run(["git", "clone", "--depth", "1", repo_url, str(dest)])


def generate_sbom(scanner: str, source_dir: Path, output_file: Path) -> None:
    output_file.parent.mkdir(parents=True, exist_ok=True)
    if scanner == "cdxgen":
        run(["cdxgen", str(source_dir), "-o", str(output_file)])
    elif scanner == "syft":
        run(["syft", f"dir:{source_dir}", "-o", f"cyclonedx-json={output_file}"])
    else:
        raise SystemExit(f"Unsupported scanner: {scanner}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", default=DEFAULT_SCOPE)
    parser.add_argument("--org", default="finos")
    parser.add_argument("--repos", default="", help="Comma-separated repo names. Overrides GitHub selection.")
    parser.add_argument("--default-demo-repos", action="store_true", help="Use a small built-in FINOS repo list.")
    parser.add_argument("--max-repos", type=int, default=20, help="0 means all repos when --repos is omitted.")
    parser.add_argument("--scanner", choices=["cdxgen", "syft"], default="cdxgen")
    parser.add_argument("--out-dir", type=Path, help="Defaults to data/sboms/<scope>.")
    parser.add_argument("--work-dir", type=Path, help="Defaults to data/local/repo-scan/<scope>.")
    parser.add_argument("--force", action="store_true", help="Delete existing cloned repos before cloning.")
    parser.add_argument("--github-token", default="", help="Optional GitHub token; falls back to gh auth token.")
    parser.add_argument("--github-api-base", default=DEFAULT_GITHUB_API)
    parser.add_argument("--github-timeout-seconds", type=int, default=25)
    parser.add_argument("--github-include-archived", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    ensure_scanner(args.scanner)

    out_dir = args.out_dir or ROOT / "data" / "sboms" / args.scope
    work_dir = args.work_dir or ROOT / "data" / "local" / "repo-scan" / args.scope
    repos = selected_repo_names(args)
    summary: Dict[str, object] = {
        "scope": args.scope,
        "org": args.org,
        "scanner": args.scanner,
        "out_dir": str(out_dir),
        "work_dir": str(work_dir),
        "repos_requested": repos,
        "sboms": [],
        "failures": [],
    }

    for repo in repos:
        repo_url = f"https://github.com/{args.org}/{repo}.git"
        repo_dir = work_dir / repo
        sbom_file = out_dir / f"{repo}.cdx.json"
        try:
            clone_or_update(repo_url, repo_dir, force=bool(args.force))
            generate_sbom(args.scanner, repo_dir, sbom_file)
            summary["sboms"].append(str(sbom_file))
        except Exception as exc:
            summary["failures"].append({"repo": repo, "error": str(exc)})

    print(json.dumps(summary, indent=2))
    return 1 if summary["failures"] and not summary["sboms"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
