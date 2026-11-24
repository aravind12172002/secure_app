import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"
APP = ROOT / "app"
TESTS = ROOT / "tests"
LOCKFILE = ROOT / "requirements.lock"
SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}
CONFIDENCE_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3}


def run(command, *, cwd=ROOT, **kwargs):
    print("+", subprocess.list2cmdline([str(part) for part in command]), flush=True)
    return subprocess.run(command, cwd=cwd, check=False, **kwargs)


def require_report(path):
    if not path.is_file() or path.stat().st_size == 0:
        raise RuntimeError(f"Required scanner report was not created: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise RuntimeError(f"Invalid JSON scanner report: {path}") from error


def sast_findings(report):
    if report.get("errors"):
        raise RuntimeError(f"Bandit reported scan errors: {report['errors']}")
    findings = report.get("results")
    metrics = report.get("metrics", {}).get("_totals", {})
    if not isinstance(findings, list) or not metrics.get("loc"):
        raise RuntimeError("Bandit did not report findings and scanned source metrics.")
    if metrics.get("skipped_tests"):
        raise RuntimeError("Bandit skipped required tests.")
    return findings


def is_blocking_sast_finding(finding):
    severity = SEVERITY_RANK.get(finding.get("issue_severity", "").upper(), 0)
    confidence = CONFIDENCE_RANK.get(
        finding.get("issue_confidence", "").upper(),
        0,
    )
    return not severity or not confidence or (
        severity >= SEVERITY_RANK["MEDIUM"] and confidence >= CONFIDENCE_RANK["MEDIUM"]
    )


def enforce_sast_policy(findings):
    blocking = [finding for finding in findings if is_blocking_sast_finding(finding)]
    warnings = [finding for finding in findings if finding not in blocking]
    for finding in warnings:
        print(
            "WARNING: SAST "
            f"{finding.get('test_id')} {finding.get('issue_severity')} "
            f"{finding.get('issue_confidence')}: {finding.get('filename')}:"
            f"{finding.get('line_number')}"
        )
    for finding in blocking:
        print(
            "BLOCKING: SAST "
            f"{finding.get('test_id')} {finding.get('issue_severity')} "
            f"{finding.get('issue_confidence')}: {finding.get('filename')}:"
            f"{finding.get('line_number')}"
        )
    if blocking:
        raise RuntimeError(f"SAST found {len(blocking)} blocking finding(s).")
    return warnings


def run_sast(targets=None, report_path=None):
    targets = targets or [APP, ROOT / "scripts"]
    report_path = report_path or REPORTS / "bandit.json"
    report_path.unlink(missing_ok=True)
    result = run(
        [
            sys.executable,
            "-m",
            "bandit",
            "-r",
            *map(str, targets),
            "-c",
            str(ROOT / "bandit.yaml"),
            "--format",
            "json",
            "--output",
            str(report_path),
            "--exit-zero",
        ]
    )
    report = require_report(report_path)
    if result.returncode:
        raise RuntimeError(f"Bandit failed to run (exit {result.returncode}).")

    findings = sast_findings(report)
    warnings = enforce_sast_policy(findings)
    print(f"SAST passed: {len(findings)} finding(s), {len(warnings)} warning(s).")


def run_sca():
    report_path = REPORTS / "pip-audit.json"
    report_path.unlink(missing_ok=True)
    result = run(
        [
            sys.executable,
            "-m",
            "pip_audit",
            "--requirement",
            str(LOCKFILE),
            "--strict",
            "--no-deps",
            "--disable-pip",
            "--format",
            "json",
            "--progress-spinner",
            "off",
            "--output",
            str(report_path),
        ]
    )
    report = require_report(report_path)
    dependencies = report.get("dependencies")
    if not isinstance(dependencies, list) or not dependencies:
        raise RuntimeError("pip-audit report is missing its dependencies list.")
    skipped = [dependency for dependency in dependencies if dependency.get("skip_reason")]
    if skipped:
        raise RuntimeError(f"pip-audit skipped {len(skipped)} dependencies.")

    findings = [
        (dependency, vulnerability)
        for dependency in dependencies
        for vulnerability in dependency.get("vulns", [])
    ]
    if result.returncode or findings:
        for dependency, vulnerability in findings:
            fixes = ", ".join(vulnerability.get("fix_versions", [])) or "not supplied"
            severity = vulnerability.get("severity") or "unrated by pip-audit"
            print(
                "BLOCKING: SCA "
                f"{dependency.get('name')}=={dependency.get('version')} "
                f"{vulnerability.get('id')} severity={severity} fixes={fixes}"
            )
        if not findings:
            print(f"pip-audit failed without a vulnerability result (exit {result.returncode}).")
        raise RuntimeError("SCA policy blocks every known vulnerability, including unrated findings.")
    print("SCA passed: no known vulnerabilities in the locked dependency set.")


def run_secret_scan():
    report_path = REPORTS / "detect-secrets.json"
    report_path.unlink(missing_ok=True)
    tracked = run(
        ["git", "-c", f"safe.directory={ROOT.as_posix()}", "ls-files", "-z"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if tracked.returncode:
        raise RuntimeError("Could not inspect tracked files before secret scanning.")
    for path in tracked.stdout.decode("utf-8").split("\0"):
        name = Path(path).name.lower()
        if name == ".env" or (name.startswith(".env.") and name != ".env.example"):
            raise RuntimeError("A local environment file is tracked; remove it from Git.")
    result = run(
        [
            sys.executable,
            "-m",
            "detect_secrets",
            "scan",
            "--all-files",
            "--no-verify",
            "--exclude-files",
            r"(^|[\\/])\.git([\\/]|$)",
            "--exclude-files",
            r"(^|[\\/])reports([\\/]|$)",
            "--exclude-files",
            r"(^|[\\/])__pycache__([\\/]|$)",
            "--exclude-files",
            r"(^|[\\/])\.pytest_cache([\\/]|$)",
            "--exclude-files",
            r"(^|[\\/])\.env(?:\.(?!example$)[^\\/]*)?$",
            "--exclude-files",
            r"(^|[\\/])instance([\\/]|$)",
            "--exclude-files",
            r"(^|[\\/])\.benchmarks([\\/]|$)",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode:
        print(result.stderr, file=sys.stderr)
        raise RuntimeError(f"Secret scanner failed (exit {result.returncode}).")
    report_path.write_text(result.stdout, encoding="utf-8")
    report = require_report(report_path)
    if not isinstance(report.get("results"), dict):
        raise RuntimeError("detect-secrets report is missing its results map.")

    findings = [
        (filename, detection)
        for filename, detections in report["results"].items()
        for detection in detections
    ]
    if findings:
        for filename, detection in findings:
            print(
                "BLOCKING: secret detection "
                f"{detection.get('type')} at {filename}:"
                f"{detection.get('line_number')}"
            )
        raise RuntimeError("Secret policy blocks every detected secret.")
    print("Secret detection passed: no findings.")


def verify_controlled_vulnerability():
    report_path = REPORTS / "controlled-vulnerability.json"
    with tempfile.TemporaryDirectory(prefix="secure-ledger-vulnerability-") as directory:
        fixture = Path(directory) / "insecure_tls.py"
        fixture.write_text(
            "import requests\n\n"
            "def request_without_tls_validation():\n"
            "    return requests.get('https://example.invalid', verify=False, timeout=1)\n",
            encoding="utf-8",
        )
        result = run(
            [
                sys.executable,
                str(Path(__file__)),
                "--sast-target",
                str(fixture),
                "--sast-report",
                str(report_path),
            ],
        )
        warning_fixture = Path(directory) / "warning.py"
        warning_fixture.write_text(
            "def check(value):\n    assert value\n",
            encoding="utf-8",
        )
        warning_result = run(
            [
                sys.executable,
                str(Path(__file__)),
                "--sast-target",
                str(warning_fixture),
                "--sast-report",
                str(REPORTS / "controlled-warning.json"),
            ],
        )
    report = require_report(report_path)
    if result.returncode != 1:
        raise RuntimeError("The controlled vulnerability did not fail the build gate.")
    warning_report = require_report(REPORTS / "controlled-warning.json")
    if warning_result.returncode or not sast_findings(warning_report):
        raise RuntimeError("The warning-only scan did not succeed with a finding.")

    findings = sast_findings(report)
    detected = [
        finding
        for finding in findings
        if finding.get("test_id") == "B501"
        and is_blocking_sast_finding(finding)
    ]
    if not detected:
        raise RuntimeError(
            "Controlled vulnerability was not detected at the configured blocking threshold."
        )
    print(
        "CONTROLLED DEMO PASSED: temporary B501 TLS-validation vulnerability "
        "exited 1; a warning-only B101 scan exited 0; fixtures were removed."
    )


def run_baseline_checks():
    checks = (
        (
            "application and custom security tests",
            [sys.executable, "-m", "pytest", "-q", str(TESTS)],
        ),
    )
    for label, command in checks:
        env = os.environ.copy()
        env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
        result = run(command, env=env)
        if result.returncode:
            raise RuntimeError(f"{label} failed (exit {result.returncode}).")

    run_sast()
    run_sca()
    run_secret_scan()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sast-target", type=Path)
    parser.add_argument("--sast-report", type=Path)
    args = parser.parse_args()
    if not LOCKFILE.is_file():
        raise RuntimeError(f"Missing dependency lockfile: {LOCKFILE}")
    REPORTS.mkdir(exist_ok=True)
    if args.sast_target:
        if args.sast_report is None:
            parser.error("--sast-report is required with --sast-target")
        run_sast([args.sast_target], args.sast_report)
        return
    if args.sast_report:
        parser.error("--sast-report requires --sast-target")

    run_baseline_checks()
    verify_controlled_vulnerability()
    print("Rechecking the restored secure baseline.")
    run_baseline_checks()
    print("Security pipeline passed.")


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as error:
        print(f"SECURITY PIPELINE FAILED: {error}", file=sys.stderr)
        sys.exit(1)
