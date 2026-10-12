#!/usr/bin/env python3
"""Validate repository-owned progress evidence; never issue certification."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

STATUS_PATH = "security/e2eesa-status.json"
ALGORITHM = "git-blob-manifest-sha256-v1"
GATES = {"unit", "adversarial", "fuzz", "secret-scan", "dependency-scan", "static-analysis"}
CONTROLS = {"SD-REQUIREMENTS", "SD-OWNERS", "SD-TOOLS", "SD-RELEASE-GATES", "SD-ENVIRONMENT", "SD-SOURCE-ACCESS", "SD-RELEASE-AUTH", "SD-ARCHIVE", "SD-DESIGN", "SD-DESIGN-REVIEW", "SD-DEPENDENCIES", "SD-SECURE-CODE", "SD-BUILD-CONFIG", "SD-CODE-REVIEW", "SD-TESTING", "SD-DEFAULTS", "SD-INTAKE", "SD-REMEDIATION", "SD-ROOT-CAUSE"}

def require(condition, message):
    if not condition:
        raise ValueError(message)

def digest(value):
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) is not None

def safe_path(value):
    return isinstance(value, str) and bool(value) and not value.startswith("/") and not any(c in value for c in "\\:\0") and all(p not in ("", ".", "..") for p in value.split("/"))

def source_fingerprint(root):
    raw = subprocess.check_output(["git", "ls-tree", "-r", "-z", "HEAD"], cwd=root)
    rows = []
    paths = set()
    for item in raw.split(b"\0"):
        if not item:
            continue
        metadata, path = item.split(b"\t", 1)
        name = path.decode("utf-8")
        if metadata.split(b" ")[0] in (b"100644", b"100755"):
            paths.add(name)
        if name == STATUS_PATH or name.startswith("security/e2eesa-evidence/"):
            continue
        rows.append((path, metadata + b"\t" + path + b"\n"))
    return hashlib.sha256(b"".join(row[1] for row in sorted(rows))).hexdigest(), paths

def validate(root, status):
    require(type(status.get("schemaVersion")) is int and status["schemaVersion"] == 1, "Unsupported schema version")
    require(re.fullmatch(r"neophilism/[A-Za-z0-9_.-]+", status.get("repository", "")), "Invalid repository identity")
    standard = status.get("standard", {})
    require(standard.get("repository") == "neophilism/End-To-End-Everywhere-Security-Architecture-Standard", "Wrong upstream standard")
    require(re.fullmatch(r"[a-f0-9]{40}", standard.get("commit", "")), "Pin an exact standard commit")
    require(standard.get("basis") in ("development", "candidate", "production"), "Unknown standard basis")
    datetime.fromisoformat(status["updatedAt"].replace("Z", "+00:00"))
    inventory = status.get("inventory", {})
    require(safe_path(inventory.get("path")) and isinstance(inventory.get("reviewed"), bool), "Invalid inventory reference")
    require((root / inventory["path"]).is_file(), "Inventory file missing")
    source = status.get("source", {})
    require("digest" in source and source.get("algorithm") == ALGORITHM and (source.get("digest") is None or digest(source["digest"])), "Invalid source binding")
    for key in ("implementation", "testing", "independentReview"):
        stage = status.get(key, {})
        require(isinstance(stage.get("complete"), bool), f"{key}: complete must be boolean")
        require(isinstance(stage.get("evidence"), list) and all(safe_path(p) for p in stage["evidence"]), f"{key}: invalid evidence paths")
        require(isinstance(stage.get("pending"), list) and all(isinstance(p, str) for p in stage["pending"]), f"{key}: pending work required")
    implementation, testing, review = (status[key] for key in ("implementation", "testing", "independentReview"))
    require(isinstance(implementation.get("controls"), list) and isinstance(testing.get("checks"), list), "Control/check lists required")
    require(isinstance(review.get("reviewers"), list) and isinstance(review.get("ownerAccepted"), bool), "Review identities/acceptance required")
    require(not testing["complete"] or implementation["complete"], "Testing depends on implementation")
    require(not review["complete"] or testing["complete"], "Expert completion depends on implemented/tested source")
    if not implementation["complete"]:
        return
    fingerprint, paths = source_fingerprint(root)
    require(source["digest"] == fingerprint, "Source changed or assessed fingerprint missing")
    dirty = subprocess.run(["git", "diff", "--quiet", "HEAD", "--", ".", ":(exclude)security/e2eesa-status.json", ":(exclude)security/e2eesa-evidence/**"], cwd=root).returncode
    require(dirty == 0, "Checked stages require a clean source checkout")
    require(inventory["reviewed"] and inventory["path"] in paths, "Component inventory review pending")
    def evidence(items):
        return bool(items) and all(safe_path(p) and p in paths and (root / p).is_file() for p in items)
    require(evidence(implementation["evidence"]), "Implementation evidence missing")
    controls = implementation["controls"]
    require(len(controls) == len(CONTROLS) and {c.get("id") for c in controls} == CONTROLS, "All 19 controls need evidence")
    require(all(c.get("state") == "implemented" and evidence(c.get("evidence", [])) for c in controls), "Control implementation evidence missing")
    if not testing["complete"]:
        return
    checks = testing["checks"]
    require(len(checks) == len(GATES) and {c.get("kind") for c in checks} == GATES, "All six required gates must pass")
    now = datetime.now(timezone.utc)
    for check in checks:
        require(check.get("status") == "passed" and check.get("sourceDigest") == fingerprint, "Failed or mismatched source gate")
        completed = datetime.fromisoformat(check["completedAt"].replace("Z", "+00:00"))
        require(completed.tzinfo is not None and 0 <= (now-completed).total_seconds() <= 7*86400, "Stale or future-dated gate")
        require(digest(check.get("toolDigest")) and digest(check.get("configurationDigest")), "Immutable tool/configuration digests required")
        require(evidence([check.get("report")]), "Test report missing")
    require(evidence(testing["evidence"]), "Complete test evidence missing")
    if review["complete"]:
        require(review["ownerAccepted"] and review.get("sourceDigest") == fingerprint, "Owner acceptance/current review source missing")
        require(review["reviewers"] and all(isinstance(r.get("name"), str) and r["name"].strip() and r.get("independent") is True and r.get("qualified") is True for r in review["reviewers"]), "Qualified independent identities required")
        require(evidence(review["evidence"]), "Authenticated expert review evidence missing")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--fingerprint", action="store_true")
    args = parser.parse_args()
    try:
        if args.fingerprint:
            print(source_fingerprint(args.root)[0])
            return 0
        path = args.root / STATUS_PATH
        require(path.stat().st_size <= 65536, "Status record exceeds size limit")
        validate(args.root, json.loads(path.read_text()))
        print("Status record integrity valid. Implementation/testing/expert claims require their own evidence; no certification issued.")
        return 0
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        print(f"Invalid E2EESA status: {error}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
