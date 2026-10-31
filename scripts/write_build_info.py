"""Write the build-time evidence manifest for the console evidence page.

The gateway MUST NOT shell out to git at request time (B6): every historic
claim on /v1/evidence/reports (recorded test count, commit, date) is read
from the JSON file this script writes. Run it in CI and in the Dockerfile
*before* packaging so the image carries its own provenance:

    python scripts/write_build_info.py [--pytest-count N] [--output PATH]

Commit resolution order: $BUILD_COMMIT, $RENDER_GIT_COMMIT, $GITHUB_SHA,
then `git rev-parse HEAD` (best effort — the Docker build context excludes
.git/, so pass the commit in via env there). The pytest count is accepted
via --pytest-count (CI fills it in after running the suite); when absent
the manifest records null and the console says "not recorded" instead of
inventing a number.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "agentshield" / "gateway" / "build_info.json"


def _git(*args: str) -> str | None:
    try:
        out = subprocess.run(["git", *args], cwd=ROOT, capture_output=True,
                             text=True, timeout=10)
        return out.stdout.strip() or None if out.returncode == 0 else None
    except Exception:
        return None


def build_info(pytest_count: int | None = None) -> dict:
    commit = (os.getenv("BUILD_COMMIT") or os.getenv("RENDER_GIT_COMMIT")
              or os.getenv("GITHUB_SHA") or _git("rev-parse", "HEAD"))
    date = _git("log", "-1", "--format=%cI")
    branch = (os.getenv("RENDER_GIT_BRANCH")
              or os.getenv("GITHUB_REF_NAME")
              or _git("rev-parse", "--abbrev-ref", "HEAD"))
    return {
        "schema_version": 1,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "generator": "scripts/write_build_info.py",
        "commit": commit,
        "commit_date": date,
        "branch": branch,
        "pytest": {
            "passed": pytest_count,
            "note": ("recorded by CI at build time; rerun "
                     "`python -m pytest tests -q` to reproduce locally"),
        },
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pytest-count", type=int, default=None,
                        help="number of passed tests recorded by CI")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT),
                        help="manifest path to write")
    args = parser.parse_args(argv)
    info = build_info(pytest_count=args.pytest_count)
    out = Path(args.output)
    out.write_text(json.dumps(info, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out} (commit={info['commit']}, "
          f"pytest_passed={info['pytest']['passed']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
