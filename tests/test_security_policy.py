import json
from types import SimpleNamespace

import pytest

from scripts.git_history_scan import sanitize_findings, scan_history
from scripts.security_pipeline import enforce_sast_policy


def test_low_confidence_or_severity_findings_are_warnings():
    low_finding = {
        "test_id": "B105",
        "issue_severity": "LOW",
        "issue_confidence": "MEDIUM",
        "filename": "example.py",
        "line_number": 1,
    }

    assert enforce_sast_policy([low_finding]) == [low_finding]


def test_medium_and_high_confidence_findings_block():
    blocking_finding = {
        "test_id": "B501",
        "issue_severity": "HIGH",
        "issue_confidence": "HIGH",
        "filename": "example.py",
        "line_number": 1,
    }

    with pytest.raises(RuntimeError, match="blocking finding"):
        enforce_sast_policy([blocking_finding])


def test_history_report_omits_secret_and_untrusted_metadata():
    private_value = "example-sensitive-value"
    findings = [
        {
            "RuleID": "aws-access-token",
            "Commit": "a" * 40,
            "File": f"secrets/{private_value}",
            "StartLine": 1,
            "EndLine": 1,
            "Secret": private_value,
            "Match": private_value,
            "Message": f"Accidentally committed {private_value}",
        }
    ]

    report = sanitize_findings(findings)

    assert private_value not in json.dumps(report)
    assert set(report[0]) == {"rule", "commit", "path_sha256", "start_line", "end_line"}
    assert report[0]["rule"] == "aws-access-token"


def test_history_report_rejects_invalid_finding_metadata():
    with pytest.raises(RuntimeError, match="invalid finding metadata"):
        sanitize_findings([{"RuleID": "aws-access-token", "Commit": "not-a-commit"}])


def test_history_scan_rejects_shallow_checkout(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "scripts.git_history_scan.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="true\n"),
    )
    report = tmp_path / "report.json"
    report.write_text("stale", encoding="utf-8")

    with pytest.raises(RuntimeError, match="shallow"):
        scan_history(tmp_path, tmp_path / "scanner", report)
    assert not report.exists()
