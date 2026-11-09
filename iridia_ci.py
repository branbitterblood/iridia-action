#!/usr/bin/env python3
"""Iridia in a CI pipeline: scan a deployed URL (or re-test it against a committed baseline),
write the reports, and pass or fail the job by a rule you choose.

    python ci/iridia_ci.py --target https://staging.example.com --fail-on new --severity high
    python ci/iridia_ci.py --baseline .iridia/baseline.json --fail-on new

Rules (--fail-on):
  new   fail on findings at/above --severity that weren't in the baseline (the default; with no
        baseline, every finding is new — commit the first scan.json as the baseline)
  open  fail on any finding at/above --severity that is still there, old or new
  none  never fail on findings (reports only)

Exit codes: 0 pass · 1 the rule failed · 2 the engine couldn't run (target unreachable, bad
input, scans of different targets) · 5 the license doesn't cover this (Team on CI runners).

Writes into --out: iridia.sarif, the Executive HTML, bugbounty .md, scan.json (the next
baseline) and summary.md; on GitHub Actions the summary also goes to the job page and the
verdict to step outputs. Standard library only — the engine does the work.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shlex
import shutil
import subprocess  # nosec B404 — runs the Iridia engine with a fixed argv
import sys
import urllib.request
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
SEV_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
NEW_STATUSES = ("introduced", "newly_covered")
OPEN_STATUSES = ("still_open", "introduced", "newly_covered")
EXIT_PASS, EXIT_FAIL, EXIT_ENGINE, EXIT_LICENSE = 0, 1, 2, 5
ENGINE_ASSET = "iridia-engine-linux-x64"
SUMS_ASSET = "SHA256SUMS"


def _download(url: str, dest: Path) -> None:
    if not url.startswith("https://") and not url.startswith("http://127.0.0.1"):
        raise SystemExit(f"refusing to download the engine over a non-HTTPS URL: {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "iridia-ci"})  # noqa: S310 — scheme checked above
    with urllib.request.urlopen(req, timeout=120) as r, open(dest, "wb") as fh:  # noqa: S310  # nosec B310
        shutil.copyfileobj(r, fh)


def fetch_engine(release_url: str, dest_dir: Path) -> Path:
    """Download the standalone Linux engine from a release (`<base>/iridia-engine-linux-x64`)
    and check it against the release's SHA256SUMS before it is ever executed."""
    if platform.system() != "Linux" or platform.machine().lower() not in ("x86_64", "amd64"):
        raise SystemExit(f"the released engine is Linux x86-64 only (this runner: "
                         f"{platform.system()} {platform.machine()})")
    base = release_url.rstrip("/")
    dest_dir.mkdir(parents=True, exist_ok=True)
    sums_path, binary = dest_dir / SUMS_ASSET, dest_dir / ENGINE_ASSET
    _download(f"{base}/{SUMS_ASSET}", sums_path)
    want = next((line.split()[0] for line in sums_path.read_text().splitlines()
                 if line.strip().endswith(ENGINE_ASSET)), None)
    if not want:
        raise SystemExit(f"{SUMS_ASSET} at {base} has no entry for {ENGINE_ASSET}")
    _download(f"{base}/{ENGINE_ASSET}", binary)
    got = hashlib.sha256(binary.read_bytes()).hexdigest()
    if got != want.lower():
        binary.unlink()
        raise SystemExit(f"checksum mismatch for {ENGINE_ASSET}: expected {want}, got {got}")
    binary.chmod(0o755)
    return binary


def engine_command(explicit: str | None, release_url: str | None = None,
                   cache: Path | None = None) -> list[str]:
    """--engine / $IRIDIA_ENGINE, else the released binary (--engine-url / $IRIDIA_ENGINE_URL,
    checksum-verified), else the engine source next to this file (a checkout of the repo),
    else a binary on PATH."""
    raw = explicit or os.environ.get("IRIDIA_ENGINE", "")
    if raw.strip():
        cmd = shlex.split(raw)
        return [sys.executable, *cmd] if cmd[0].endswith(".py") else cmd
    url = release_url or os.environ.get("IRIDIA_ENGINE_URL", "")
    if url.strip():
        return [str(fetch_engine(url.strip(), cache or Path(".iridia-engine")))]
    source = HERE.parent / "src-tauri" / "resources" / "iridia.py"
    if source.exists():
        return [sys.executable, str(source)]
    for name in ("iridia-engine", "ird"):
        found = shutil.which(name)
        if found:
            return [found]
    raise SystemExit("Iridia engine not found: pass --engine or set IRIDIA_ENGINE")


def run_engine(engine: list[str], args: list[str]) -> tuple[int, str, str]:
    proc = subprocess.run([*engine, *args], capture_output=True, text=True, encoding="utf-8",  # nosec B603
                          errors="replace", timeout=1800, check=False)
    return proc.returncode, proc.stdout, proc.stderr


def _json(stdout: str) -> dict[str, Any] | None:
    try:
        v = json.loads(stdout.strip() or "null")
    except json.JSONDecodeError:
        return None
    return v if isinstance(v, dict) else None


def scope_args(a: argparse.Namespace) -> list[str]:
    out: list[str] = []
    for s in a.scope:
        out += ["--scope", s]
    if a.accept_roe:
        out.append("--accept-roe")
    return out


def blocking(items: list[dict[str, Any]], statuses: tuple[str, ...], threshold: str) -> list[dict[str, Any]]:
    floor = SEV_RANK[threshold.upper()]
    return [i for i in items if i.get("status") in statuses and SEV_RANK.get(i.get("severity", ""), 0) >= floor]


def gate(items: list[dict[str, Any]], fail_on: str, threshold: str) -> list[dict[str, Any]]:
    """The findings that fail the job under the rule (empty = pass)."""
    if fail_on == "none":
        return []
    return blocking(items, NEW_STATUSES if fail_on == "new" else OPEN_STATUSES, threshold)


def items_without_baseline(scan: dict[str, Any]) -> list[dict[str, Any]]:
    return [{"code": f.get("code"), "title": f.get("title"), "severity": f.get("severity"),
             "status": "introduced", "reason": None} for f in scan.get("findings", [])]


def summary_md(target: str, scan: dict[str, Any], items: list[dict[str, Any]], failing: list[dict[str, Any]],
               rule: str, verdict: str | None, license_note: str) -> str:
    def count(*st: str) -> int:
        return sum(1 for i in items if i["status"] in st and SEV_RANK.get(i["severity"], 0) >= 1)
    head = "❌ Iridia: the job fails" if failing else "✅ Iridia: passed"
    lines = [f"### {head}", "",
             f"`{target}` · score **{scan.get('score', '?')}** (grade {scan.get('grade', '?')}) · rule: {rule}",
             ""]
    if verdict:
        lines.append(f"Re-test against the baseline: **{verdict}** — {count('fixed')} fixed, "
                     f"{count('still_open')} still open, {count(*NEW_STATUSES)} new, "
                     f"{count('not_retested')} not re-tested")
        lines.append("")
    if failing:
        lines += ["| Severity | Code | Finding | Status |", "|---|---|---|---|"]
        lines += [f"| {i['severity']} | `{i['code']}` | {i['title']} | {i['status'].replace('_', ' ')} |"
                  for i in failing]
        lines.append("")
    if license_note:
        lines += [f"> {license_note}", ""]
    lines.append("Full report: the `iridia` artifact (Executive HTML, SARIF, scan.json).")
    return "\n".join(lines) + "\n"


def license_note(engine: list[str]) -> str:
    _, out, _ = run_engine(engine, ["license", "show", "--json"])
    info = (_json(out) or {}).get("license") or {}
    if info.get("tier") == "team":
        return ""
    reason = info.get("reason") or "no license key"
    return (f"Running as Iridia Community ({reason}). Login/BOLA checks, re-tests against a "
            "baseline and stack patches on CI runners need a Team key in IRIDIA_LICENSE.")


def github_outputs(**values: str) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.writelines(f"{k}={v}\n" for k, v in values.items())


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--target", help="URL to scan (with --baseline: defaults to the baseline's target)")
    p.add_argument("--baseline", help="a previous scan.json to re-test against (needs Team on CI)")
    p.add_argument("--fail-on", choices=("new", "open", "none"), default="new")
    p.add_argument("--severity", choices=("low", "medium", "high", "critical"), default="high")
    p.add_argument("--out", default="iridia-out")
    p.add_argument("--passive", action="store_true", help="passive checks only")
    p.add_argument("--scope", action="append", default=[], help="authorized scope pattern (repeatable)")
    p.add_argument("--accept-roe", action="store_true",
                   help="confirm you are authorized to run active checks on --scope")
    p.add_argument("--engine", default=None, help="engine command (default: auto)")
    p.add_argument("--engine-url", default=None,
                   help="release URL to download the Linux engine from (checked against its SHA256SUMS)")
    a = p.parse_args(argv)
    if not a.target and not a.baseline:
        p.error("give --target, --baseline, or both")

    out = Path(a.out)
    engine = engine_command(a.engine, a.engine_url, out.parent / ".iridia-engine")
    out.mkdir(parents=True, exist_ok=True)
    note = license_note(engine)
    verdict: str | None = None

    if a.baseline:
        args = ["retest", a.baseline, "--json", "--format", "all", "--out", str(out), *scope_args(a)]
        code, stdout, stderr = run_engine(engine, args)
        res = _json(stdout)
        if code == EXIT_LICENSE or res is None or "diff" not in res:
            sys.stderr.write(stderr)
            if res and res.get("error"):
                print(f"iridia: {res['error']}", file=sys.stderr)
            return EXIT_LICENSE if code == EXIT_LICENSE else EXIT_ENGINE
        scan, diff = res["scan"], res["diff"]
        if not diff.get("comparable", True):
            print(f"iridia: the baseline is for another target ({diff.get('reason')})", file=sys.stderr)
            return EXIT_ENGINE
        items, verdict = diff["items"], res["verdict"]
        for f in res.get("written", []):
            if Path(f).name.endswith(".json") and "scan" in Path(f).name:
                shutil.copyfile(f, out / "scan.json")
    else:
        scan_args = ["scan", a.target, "--json", *scope_args(a)]
        if a.passive:
            scan_args.append("--no-active")
        code, stdout, stderr = run_engine(engine, scan_args)
        scan_res = _json(stdout)
        if code == EXIT_LICENSE or scan_res is None or "findings" not in scan_res:
            sys.stderr.write(stderr)
            if scan_res and scan_res.get("error"):
                print(f"iridia: {scan_res['error']}", file=sys.stderr)
            return EXIT_LICENSE if code == EXIT_LICENSE else EXIT_ENGINE
        scan = scan_res
        (out / "scan.json").write_text(json.dumps(scan, ensure_ascii=False, indent=2), encoding="utf-8")
        code, _, stderr = run_engine(engine, ["report", "--from-json", str(out / "scan.json"),
                                              "--format", "all", "--out", str(out), "--json"])
        if code != 0:
            sys.stderr.write(stderr)
        items = items_without_baseline(scan)

    failing = gate(items, a.fail_on, a.severity)
    rule = "none" if a.fail_on == "none" else f"fail on {a.fail_on} findings ≥ {a.severity.upper()}"
    md = summary_md(scan.get("final_url") or scan.get("target", "?"), scan, items, failing, rule, verdict, note)
    (out / "summary.md").write_text(md, encoding="utf-8")
    print(md)
    step = os.environ.get("GITHUB_STEP_SUMMARY")
    if step:
        with open(step, "a", encoding="utf-8") as fh:
            fh.write(md)
    sarif = next(iter(sorted(out.glob("*.sarif"))), None)
    github_outputs(result="fail" if failing else "pass", failing=str(len(failing)),
                   score=str(scan.get("score", "")), verdict=verdict or "",
                   sarif=str(sarif) if sarif else "", baseline=str(out / "scan.json"))
    return EXIT_FAIL if failing else EXIT_PASS


if __name__ == "__main__":
    sys.exit(main())
