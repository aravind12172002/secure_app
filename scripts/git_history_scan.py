import argparse
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def sanitize_findings(findings):
    if not isinstance(findings, list):
        raise RuntimeError("Gitleaks report is not a list of findings.")

    sanitized = []
    for finding in findings:
        if not isinstance(finding, dict):
            raise RuntimeError("Gitleaks report contains an invalid finding.")
        rule = finding.get("RuleID")
        commit = finding.get("Commit")
        path = finding.get("File")
        start_line = finding.get("StartLine")
        end_line = finding.get("EndLine")
        if (
            not isinstance(rule, str)
            or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,80}", rule)
            or not isinstance(commit, str)
            or not re.fullmatch(r"[0-9a-f]{40,64}", commit)
            or not isinstance(path, str)
            or not path
            or type(start_line) is not int
            or type(end_line) is not int
            or start_line < 1
            or end_line < start_line
        ):
            raise RuntimeError("Gitleaks report contains invalid finding metadata.")
        sanitized.append(
            {
                "rule": rule,
                "commit": commit,
                "path_sha256": hashlib.sha256(path.encode("utf-8")).hexdigest(),
                "start_line": start_line,
                "end_line": end_line,
            }
        )
    return sanitized


def scan_history(root, scanner, report_path):
    report_path.unlink(missing_ok=True)
    shallow = subprocess.run(
        ["git", "-c", f"safe.directory={root.as_posix()}", "rev-parse", "--is-shallow-repository"],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    if shallow.returncode or shallow.stdout.strip() != "false":
        raise RuntimeError("Git history is unavailable or shallow; fetch the full history.")

    with tempfile.TemporaryDirectory(prefix="gitleaks-history-") as directory:
        temporary = Path(directory)
        config = temporary / "gitleaks.toml"
        config.write_text("[extend]\nuseDefault = true\n", encoding="utf-8")
        raw_report = temporary / "report.json"
        result = subprocess.run(
            [
                str(scanner),
                "git",
                "--log-opts=--all HEAD",
                "--redact=100",
                "--exit-code=2",
                "--no-banner",
                "--no-color",
                "--ignore-gitleaks-allow",
                "--config",
                str(config),
                "--gitleaks-ignore-path",
                str(temporary),
                "--report-format=json",
                "--report-path",
                str(raw_report),
                str(root),
            ],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode not in (0, 2):
            raise RuntimeError(f"Gitleaks failed to scan Git history (exit {result.returncode}).")
        if not raw_report.is_file():
            raise RuntimeError("Gitleaks did not create its required report.")
        try:
            findings = sanitize_findings(json.loads(raw_report.read_text(encoding="utf-8")))
        except json.JSONDecodeError as error:
            raise RuntimeError("Gitleaks produced an invalid JSON report.") from error

    if bool(findings) != (result.returncode == 2):
        raise RuntimeError("Gitleaks exit status does not match its report.")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(findings, indent=2) + "\n", encoding="utf-8")
    if findings:
        raise RuntimeError(f"Git history scan found {len(findings)} possible secret(s).")
    print("Git history scan passed: no secrets found.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("scanner", type=Path)
    args = parser.parse_args()
    try:
        scan_history(ROOT, args.scanner, ROOT / "reports" / "gitleaks.json")
    except RuntimeError as error:
        parser.exit(1, f"GIT HISTORY SCAN FAILED: {error}\n")
