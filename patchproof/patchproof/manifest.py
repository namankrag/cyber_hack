"""Fixtures manifest: allowlisted fixture dirs + sha256 per file, fail-closed.

The old single-file allowlist (`vulnbank/app.py` or nothing) could not grow
past one app. The manifest lists every bundled practice fixture by directory
with a sha256 pin per fixture file, and execution is allowed only for:

  1. a path that matches a manifest entry *and* whose content hashes match, or
  2. SecureAI's isolated remediation copies (temporary `*_app.py` files the
     closed loop writes under its own temp directory for verify-then-apply).

Anything else fails closed with ValueError — the pipeline never imports,
executes, or patches it. The verifier and pipeline only ever operate on
isolated copies, so a tampered fixture is refused before any exploit runs.

Manifest format (patchproof/fixtures.json)::

    {"version": 1,
     "fixtures": {"<fixture_id>": {"dir": "<subdir of patchproof/>",
                                   "files": {"<relpath>": "<sha256>"}}}}

After editing a fixture file, re-stamp its hash (dev-time)::

    python -m patchproof.manifest --refresh

See patchproof/SECURITY.md for the trust model.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

MANIFEST_FILENAME = "fixtures.json"

# Temporary copies the SecureAI closed loop verifies before applying. The name
# pattern is owned by secureai/loop.py (sibling code); the manifest honors it
# so the loop's isolated temp copies keep working.
_LOOP_COPY_NAMES = {"vulnbank_app.py", "shopapi_app.py"}
_LOOP_COPY_PARENT_PREFIX = "secureai-remediation-"


def manifest_path() -> Path:
    return Path(__file__).resolve().parent.parent / MANIFEST_FILENAME


def patchproof_dir() -> Path:
    return Path(__file__).resolve().parent.parent


def load_manifest() -> dict:
    path = manifest_path()
    if not path.is_file():
        raise ValueError(
            "PatchProof fixtures manifest is missing: "
            f"{path}. Refusing to execute anything (fail-closed).")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(
            f"PatchProof fixtures manifest is unreadable: {exc}. "
            "Refusing to execute anything (fail-closed).") from exc
    if not isinstance(data, dict) or data.get("version") != 1:
        raise ValueError(
            "PatchProof fixtures manifest has an unsupported version. "
            "Refusing to execute anything (fail-closed).")
    return data


def fixture_id_for_path(path: str | Path) -> str | None:
    """Return the manifest fixture id owning `path` (directory match only)."""
    target = Path(path).resolve()
    root = patchproof_dir().resolve()
    try:
        rel = target.relative_to(root)
    except ValueError:
        return None
    for fixture_id, entry in load_manifest()["fixtures"].items():
        if rel.parts and rel.parts[0] == entry.get("dir"):
            return fixture_id
    return None


def _hash_ok(target: Path, expected: str) -> bool:
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    return digest == expected


def assert_bundled_fixture_target(path: str | Path) -> Path:
    """Allow execution only for manifest-pinned fixtures or loop temp copies.

    Raises ValueError (fail-closed) for anything else: unknown files, files
    outside the fixture dirs, and manifest-listed files whose content no
    longer matches the pinned sha256.
    """
    target = Path(path).resolve()
    root = patchproof_dir().resolve()
    try:
        rel = target.relative_to(root)
    except ValueError:
        rel = None
    if rel is not None:
        for fixture_id, entry in load_manifest()["fixtures"].items():
            files = entry.get("files", {})
            if rel.parts and rel.parts[0] == entry.get("dir") and rel.name in files:
                expected = files[rel.name]
                if target.is_file() and _hash_ok(target, expected):
                    return target
                raise ValueError(
                    "Refusing to execute "
                    f"{target}: content does not match the sha256 pinned in "
                    f"{MANIFEST_FILENAME} for fixture '{fixture_id}'. "
                    "Re-stamp the manifest after editing a fixture, or "
                    "restore the fixture file."
                )
    if (target.name in _LOOP_COPY_NAMES
            and target.parent.name.startswith(_LOOP_COPY_PARENT_PREFIX)):
        return target
    raise ValueError(
        "Exploit and candidate execution is limited to the manifest-listed "
        f"PatchProof fixtures ({MANIFEST_FILENAME}) and SecureAI's isolated "
        f"remediation copies. Refusing: {target}"
    )


def refresh_manifest() -> dict:
    """Recompute sha256 pins from the current fixture files and save.

    Dev-time helper: run after intentionally editing a fixture, then review
    the fixtures.json diff before committing.
    """
    data = load_manifest()
    root = patchproof_dir()
    for fixture_id, entry in data["fixtures"].items():
        for relname in list(entry.get("files", {})):
            target = root / entry["dir"] / relname
            if not target.is_file():
                raise FileNotFoundError(
                    f"fixture file missing: {target} (fixture '{fixture_id}')")
            entry["files"][relname] = hashlib.sha256(
                target.read_bytes()).hexdigest()
    manifest_path().write_text(json.dumps(data, indent=2) + "\n",
                               encoding="utf-8")
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="patchproof.manifest")
    parser.add_argument("--refresh", action="store_true",
                        help="re-stamp sha256 pins from current fixture files")
    parser.add_argument("--check", action="store_true",
                        help="verify every pinned file exists and matches")
    args = parser.parse_args(argv)
    if args.refresh:
        data = refresh_manifest()
        print(f"refreshed {manifest_path()}: "
              f"{sum(len(e['files']) for e in data['fixtures'].values())} file(s)")
        return 0
    if args.check:
        data = load_manifest()
        root = patchproof_dir()
        bad = []
        for fixture_id, entry in data["fixtures"].items():
            for relname, expected in entry.get("files", {}).items():
                target = root / entry["dir"] / relname
                if not target.is_file() or not _hash_ok(target, expected):
                    bad.append(f"{entry['dir']}/{relname}")
        if bad:
            print("MISMATCH: " + ", ".join(bad))
            return 1
        print("manifest check ok")
        return 0
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
