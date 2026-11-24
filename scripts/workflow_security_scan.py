import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SEVERITY = {"Informational": 1, "Low": 2, "Medium": 3, "High": 4}
CONFIDENCE = {"Low": 1, "Medium": 2, "High": 3}


def sanitize_findings(findings):
    if not isinstance(findings, list):
        raise RuntimeError("zizmor report is not a list of findings.")
    sanitized = []
    for finding in findings:
        if not isinstance(finding, dict):
            raise RuntimeError("zizmor report contains an invalid finding.")
        rule = finding.get("ident")
        determination = finding.get("determinations")
        locations = finding.get("locations")
        if (
            not isinstance(rule, str)
            or not re.fullmatch(r"[a-z][a-z0-9-]{0,80}", rule)
            or not isinstance(determination, dict)
            or determination.get("severity") not in SEVERITY
            or determination.get("confidence") not in CONFIDENCE
            or not isinstance(locations, list)
            or not locations
            or finding.get("ignored") is not False
        ):
            raise RuntimeError("zizmor report contains invalid finding metadata.")
        safe_locations = []
        for location in locations:
            try:
                path = location["symbolic"]["key"]["Local"]["verbatim_path"]
                row = location["concrete"]["location"]["start_point"]["row"]
            except (KeyError, TypeError) as error:
                raise RuntimeError("zizmor report contains an invalid location.") from error
            if not isinstance(path, str) or not path or type(row) is not int or row < 0:
                raise RuntimeError("zizmor report contains an invalid location.")
            safe_locations.append(
                {
                    "path_sha256": hashlib.sha256(path.encode("utf-8")).hexdigest(),
                    "line": row + 1,
                }
            )
        sanitized.append(
            {
                "rule": rule,
                "severity": determination["severity"],
                "confidence": determination["confidence"],
                "locations": safe_locations,
            }
        )
    return sanitized


def scan_workflows(root, scanner, report_path):
    report_path.unlink(missing_ok=True)
    directory = root / ".github" / "workflows"
    workflows = sorted([*directory.glob("*.yml"), *directory.glob("*.yaml")])
    if not workflows:
        raise RuntimeError("No GitHub Actions workflows were found.")

    result = subprocess.run(
        [
            str(scanner),
            "--offline",
            "--strict-collection",
            "--no-config",
            "--no-ignores",
            "--no-progress",
            "--format=json-v1",
            *map(str, workflows),
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode not in (0, 11, 12, 13, 14):
        raise RuntimeError(f"zizmor failed to scan workflows (exit {result.returncode}).")
    try:
        findings = sanitize_findings(json.loads(result.stdout))
    except json.JSONDecodeError as error:
        raise RuntimeError("zizmor produced an invalid JSON report.") from error

    expected_exit = max((10 + SEVERITY[item["severity"]] for item in findings), default=0)
    if result.returncode != expected_exit:
        raise RuntimeError("zizmor exit status does not match its report.")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(findings, indent=2) + "\n", encoding="utf-8")

    blocking = []
    for finding in findings:
        is_blocking = (
            SEVERITY[finding["severity"]] >= SEVERITY["Medium"]
            and CONFIDENCE[finding["confidence"]] >= CONFIDENCE["Medium"]
        )
        label = "BLOCKING" if is_blocking else "WARNING"
        print(f"{label}: workflow {finding['rule']} {finding['severity']} {finding['confidence']}")
        if is_blocking:
            blocking.append(finding)
    if blocking:
        raise RuntimeError(f"Workflow scan found {len(blocking)} blocking finding(s).")
    print(f"Workflow scan passed: {len(findings)} warning(s).")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("scanner", type=Path)
    args = parser.parse_args()
    try:
        scan_workflows(ROOT, args.scanner, ROOT / "reports" / "zizmor.json")
    except RuntimeError as error:
        parser.exit(1, f"WORKFLOW SCAN FAILED: {error}\n")
