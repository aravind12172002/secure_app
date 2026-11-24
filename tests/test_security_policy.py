import json
from types import SimpleNamespace

import pytest

from scripts.git_history_scan import sanitize_findings, scan_history
from scripts.security_pipeline import enforce_sast_policy
from scripts.workflow_security_scan import sanitize_findings as sanitize_workflow_findings
from scripts.workflow_security_scan import scan_workflows


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


def test_workflow_report_omits_workflow_source_and_paths():
    private_value = "example-sensitive-value"
    findings = [
        {
            "ident": "template-injection",
            "determinations": {"severity": "High", "confidence": "High"},
            "ignored": False,
            "locations": [
                {
                    "symbolic": {"key": {"Local": {"verbatim_path": private_value}}},
                    "concrete": {
                        "location": {"start_point": {"row": 4}},
                        "feature": private_value,
                    },
                }
            ],
        }
    ]

    report = sanitize_workflow_findings(findings)

    assert private_value not in json.dumps(report)
    assert report[0]["rule"] == "template-injection"
    assert report[0]["locations"][0]["line"] == 5


def test_workflow_report_rejects_invalid_severity():
    with pytest.raises(RuntimeError, match="invalid finding metadata"):
        sanitize_workflow_findings(
            [
                {
                    "ident": "template-injection",
                    "determinations": {"severity": "Unexpected", "confidence": "High"},
                    "locations": [{}],
                    "ignored": False,
                }
            ]
        )


@pytest.mark.parametrize(
    ("severity", "confidence", "exit_code", "blocks"),
    [("High", "High", 14, True), ("Medium", "Low", 13, False), ("Low", "High", 12, False)],
)
def test_workflow_scan_enforces_thresholds(
    monkeypatch, tmp_path, severity, confidence, exit_code, blocks
):
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "test.yml").write_text("name: test\n", encoding="utf-8")
    report = tmp_path / "report.json"
    findings = [
        {
            "ident": "template-injection",
            "determinations": {"severity": severity, "confidence": confidence},
            "ignored": False,
            "locations": [
                {
                    "symbolic": {"key": {"Local": {"verbatim_path": "test.yml"}}},
                    "concrete": {"location": {"start_point": {"row": 0}}},
                }
            ],
        }
    ]
    monkeypatch.setattr(
        "scripts.workflow_security_scan.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=exit_code, stdout=json.dumps(findings)
        ),
    )

    if blocks:
        with pytest.raises(RuntimeError, match="blocking finding"):
            scan_workflows(tmp_path, tmp_path / "scanner", report)
    else:
        scan_workflows(tmp_path, tmp_path / "scanner", report)
    assert json.loads(report.read_text(encoding="utf-8"))[0]["severity"] == severity
