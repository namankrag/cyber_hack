"""Finding-card renderer tests (PS-02 evidence style)."""
import json

from scripts.render_findings import render


def _sample(path, results):
    path.write_text(json.dumps({"version": "1", "results": results,
                                "errors": []}), encoding="utf-8")


def test_clean_report_states_gate_clean(tmp_path):
    p = tmp_path / "s.json"
    _sample(p, [])
    out = render(p)
    assert "0" in out and "clean" in out


def test_card_names_rule_location_and_taxonomy(tmp_path):
    p = tmp_path / "s.json"
    _sample(p, [{"check_id": "python.flask.security.injection.sqli",
                 "path": "app.py", "start": {"line": 42},
                 "extra": {"message": "user input flows to query",
                           "severity": "ERROR",
                           "metadata": {"cwe": "CWE-89",
                                        "owasp": "A03:2021"}}}])
    out = render(p)
    assert "python.flask.security.injection.sqli" in out
    assert "app.py:42" in out
    assert "CWE-89" in out and "A03:2021" in out
