import pytest

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
