"""Benchmark harness (PS-01 item 2) tests: cases, scoring, bench endpoint."""
import importlib
import json
import os
import subprocess
import sys
from pathlib import Path

from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parent.parent
CASES = REPO_ROOT / "bench" / "cases.jsonl"


def _read_cases():
    with open(CASES, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def test_cases_file_valid_and_sized():
    cases = _read_cases()
    assert 60 <= len(cases) <= 100, len(cases)
    ids = [c["id"] for c in cases]
    assert len(set(ids)) == len(ids)
    for c in cases:
        assert set(c) >= {"id", "label", "attack_type", "tool", "source",
                          "arguments", "context", "expected_decision"}
        assert c["label"] in {"benign", "malicious", "approval"}
        assert c["expected_decision"] in {"allow", "deny", "require_approval"}
        assert isinstance(c["arguments"], dict) and isinstance(c["context"], str)


def test_cases_coverage_meets_brief():
    cases = _read_cases()
    by_label = {}
    for c in cases:
        by_label.setdefault(c["label"], []).append(c)
    assert len(by_label["benign"]) >= 30
    attacks = {c["attack_type"] for c in by_label["malicious"]}
    for required in ("direct_injection", "indirect_injection", "exfil",
                     "permission_escalation", "encoded", "obfuscated"):
        assert required in attacks, required
    for lang in ("i18n-hi", "i18n-kn", "i18n-ta", "i18n-te"):
        assert sum(1 for c in cases if c["attack_type"] == lang) >= 2, lang
    appr = [c for c in by_label["approval"]
            if c["attack_type"] == "legitimate_high_impact"]
    assert len(appr) >= 2
    assert {c["expected_decision"] for c in appr} == {"require_approval"}
    tools = {c["tool"] for c in by_label["benign"]}
    assert len(tools) >= 3  # varied tools, not one golden path
    sources = {c["source"] for c in by_label["benign"]}
    assert len(sources) >= 2  # varied sources


def test_percentile_and_summarize_units():
    sys.path.insert(0, str(REPO_ROOT))
    from scripts.benchmark import percentile, summarize
    assert percentile([1.0, 2.0, 3.0, 4.0], 50) == 2.0
    assert percentile([], 95) == 0.0
    cases = [
        {"id": "m1", "label": "malicious"},
        {"id": "b1", "label": "benign"},
        {"id": "a1", "label": "approval"},
    ]
    rows = [
        {"id": "m1", "actual_on": "deny", "actual_off": "allow",
         "latency_ms_on": 1.0, "latency_ms_off": 0.5, "match_on": True},
        {"id": "b1", "actual_on": "allow", "actual_off": "allow",
         "latency_ms_on": 2.0, "latency_ms_off": 0.5, "match_on": True},
        {"id": "a1", "actual_on": "require_approval", "actual_off": "allow",
         "latency_ms_on": 3.0, "latency_ms_off": 0.5, "match_on": True},
    ]
    s = summarize(cases, rows)
    assert s["attack_success_off"] == 1.0
    assert s["attack_success_on"] == 0.0
    assert s["attack_denied_on"] == 1.0
    assert s["false_positive_rate_benign"] == 0.0
    assert s["false_hold_rate_benign"] == 0.0
    assert s["approval_correctness"] == 1.0
    assert s["latency_ms_on"]["p50"] == 2.0


def test_load_cases_rejects_bad_file(tmp_path):
    sys.path.insert(0, str(REPO_ROOT))
    from scripts.benchmark import load_cases
    bad = tmp_path / "bad.jsonl"
    bad.write_text('{"id": "x"}\n', encoding="utf-8")
    try:
        load_cases(bad)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for missing fields")


def test_harness_errors_exit_nonzero(tmp_path):
    bad = tmp_path / "bad.jsonl"
    bad.write_text("not json\n", encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "benchmark.py"),
         "--cases", str(bad), "--out-dir", str(tmp_path)],
        capture_output=True, text=True, cwd=str(REPO_ROOT))
    assert proc.returncode == 2
    assert "harness error" in proc.stderr


def _client(tmp_path, monkeypatch, api_key=None, bench_dir=None):
    for var in ("AGENTSHIELD_API_KEY", "AGENTSHIELD_ADMIN_KEY",
                "AGENTSHIELD_HARNESS_SECRET", "AGENTSHIELD_BENCH_DIR"):
        monkeypatch.delenv(var, raising=False)
    if api_key is not None:
        monkeypatch.setenv("AGENTSHIELD_API_KEY", api_key)
    if bench_dir is not None:
        monkeypatch.setenv("AGENTSHIELD_BENCH_DIR", str(bench_dir))
    monkeypatch.setenv("AGENTSHIELD_AUDIT_PATH",
                       os.path.join(str(tmp_path), "audit.jsonl"))
    import agentshield.gateway.app as appmod
    importlib.reload(appmod)
    return TestClient(appmod.app)


def _write_results(bench_dir: Path, name="results_20261030T000000Z.json"):
    stamp = name[len("results_"):-len(".json")]
    payload = {"generated_at_utc": stamp, "n_cases": 1,
               "summary": {"n_total": 1, "attack_success_off": 1.0,
                           "attack_success_on": 0.0,
                           "false_positive_rate_benign": 0.0,
                           "false_hold_rate_benign": 0.0,
                           "latency_ms_on": {"p50": 0.5, "p95": 0.5,
                                             "p99": 0.5}},
               "cases": []}
    (bench_dir / name).write_text(json.dumps(payload), encoding="utf-8")
    return payload


def test_bench_latest_none_when_no_results(tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch, bench_dir=tmp_path / "empty-bench")
    body = c.get("/v1/bench/latest").json()
    assert body == {"latest": None}


def test_bench_latest_serves_newest(tmp_path, monkeypatch):
    bench = tmp_path / "bench"
    bench.mkdir()
    _write_results(bench, "results_20261030T000000Z.json")
    newest = _write_results(bench, "results_20261030T010000Z.json")
    c = _client(tmp_path, monkeypatch, bench_dir=bench)
    body = c.get("/v1/bench/latest").json()
    assert body["latest"]["generated_at_utc"] == "20261030T010000Z"
    assert body["latest"]["summary"] == newest["summary"]


def test_bench_latest_requires_key_when_configured(tmp_path, monkeypatch):
    bench = tmp_path / "bench"
    bench.mkdir()
    _write_results(bench)
    c = _client(tmp_path, monkeypatch, api_key="t", bench_dir=bench)
    assert c.get("/v1/bench/latest").status_code == 401
    r = c.get("/v1/bench/latest", headers={"X-API-Key": "t"})
    assert r.status_code == 200
    assert r.json()["latest"]["n_cases"] == 1


def test_dashboard_embeds_benchmark_panel(tmp_path, monkeypatch):
    bench = tmp_path / "bench"
    bench.mkdir()
    _write_results(bench)
    c = _client(tmp_path, monkeypatch, bench_dir=bench)
    html = c.get("/").text
    assert "Benchmark" in html
    assert "/v1/bench/latest" in html
