#!/usr/bin/env python3
"""Validate a NON-CONFORMANT provisional source inventory without certifying it."""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = Path("security/e2eesa-inventory.json")
STATUS = Path("security/e2eesa-status.json")
CLASSES = {"protected", "public", "intentionally-disclosed"}
STATES = {"implemented-local", "partial-contract", "public-only", "host-required"}
TOP = {
    "schemaVersion", "repository", "classificationStatus", "coverageComplete",
    "observedAt", "upstreamReference", "components", "dataFlows",
    "sourceObservations", "limitations",
}
COMPONENT = {"id", "paths", "dataClasses", "implementationState", "boundary"}
FLOW = {"id", "from", "to", "dataClass", "networked", "evidencePaths", "scopeNote"}
OBSERVATION = {"path", "blobSha"}


def safe_path(s):
    return (
        isinstance(s, str) and bool(s) and not s.startswith("/")
        and not any(ch in s for ch in "\\\x00:")
        and all(seg not in ("", ".", "..") for seg in s.split("/"))
    )


def validate(data, root=ROOT, status=None):
    """Return fail-closed structural errors; this is NOT a completeness assessment."""
    errors = []
    if not isinstance(data, dict) or set(data) != TOP:
        return ["Inventory root fields are not the provisional v1 schema."]
    if data["schemaVersion"] != 1 or data["repository"] != "neophilism/End-To-End-Everywhere-Suite":
        errors.append("Unexpected provisional inventory version or repository.")
    if data["classificationStatus"] != "preliminary" or data["coverageComplete"] is not False:
        errors.append("Provisional discovery cannot assert reviewed or complete coverage.")
    if not isinstance(data["observedAt"], str) or not re.fullmatch(r"20\d{2}-\d{2}-\d{2}", data["observedAt"]):
        errors.append("Missing ISO day for source observation.")
    upstream = data["upstreamReference"]
    if (
        not isinstance(upstream, dict)
        or upstream.get("repository") != "neophilism/End-To-End-Everywhere-Security-Architecture-Standard"
        or not re.fullmatch(r"[0-9a-f]{40}", upstream.get("commit", ""))
        or upstream.get("relationship") != "discovery-only; not a 0.2 conformance request"
    ):
        errors.append("An exact upstream development pin and non-conformance label are required.")
    if not isinstance(data["limitations"], list) or len(data["limitations"]) < 3 or not all(isinstance(s, str) and s.strip() for s in data["limitations"]):
        errors.append("Explicit product and assessment limitations are required.")
    if status is not None:
        inv = status.get("inventory", {}) if isinstance(status, dict) else {}
        if inv.get("reviewed") is not False or inv.get("path") != INVENTORY.as_posix():
            errors.append("Status must keep the preliminary inventory review pending.")

    components = data["components"]
    ids = set()
    referenced_paths = set()
    if not isinstance(components, list) or len(components) < 14:
        return errors + ["Expected a source-backed entry for every Rust workspace crate and host boundary."]
    for c in components:
        if not isinstance(c, dict) or set(c) != COMPONENT:
            errors.append("Component fields mismatch.")
            continue
        cid = c["id"]
        if not isinstance(cid, str) or not re.fullmatch(r"[a-z0-9-]{2,64}", cid) or cid in ids:
            errors.append("Duplicate or invalid component id.")
            continue
        ids.add(cid)
        if c["implementationState"] not in STATES:
            errors.append(cid + ": unsupported implementation state.")
        classes = c["dataClasses"]
        if not isinstance(classes, list) or not classes or len(classes) != len(set(classes)) or not set(classes) <= CLASSES:
            errors.append(cid + ": invalid classified data domains.")
        if not isinstance(c["boundary"], str) or len(c["boundary"].strip()) < 18:
            errors.append(cid + ": missing trust-boundary disclaimer.")
        paths = c["paths"]
        if not isinstance(paths, list) or not paths or len(paths) != len(set(paths)):
            errors.append(cid + ": missing/duplicate component paths.")
            continue
        for p in paths:
            if not safe_path(p) or (root / p).is_symlink() or not (root / p).is_file():
                errors.append(cid + ": missing/unsafe evidence path: " + str(p))
            else:
                referenced_paths.add(p)

    flows = data["dataFlows"]
    flowids = set()
    if not isinstance(flows, list) or len(flows) < 8:
        return errors + ["Provisional inventory omitted known flow classes."]
    for flow in flows:
        if not isinstance(flow, dict) or set(flow) != FLOW:
            errors.append("Data flow fields mismatch.")
            continue
        fid = flow["id"]
        if not isinstance(fid, str) or not re.fullmatch(r"[a-z0-9-]{2,64}", fid) or fid in flowids:
            errors.append("Duplicate/invalid flow identifier.")
            continue
        flowids.add(fid)
        if flow["from"] not in ids or flow["to"] not in ids:
            errors.append(fid + ": unknown component endpoint.")
        if flow["dataClass"] not in CLASSES or not isinstance(flow["networked"], bool):
            errors.append(fid + ": unsupported flow classification.")
        # The source-backed Suite has no implemented networked private-content
        # endpoint/relay service. This invariant must be revisited explicitly
        # when real network services exist and receive security assessment.
        if flow["networked"] is True and flow["dataClass"] == "protected":
            errors.append(fid + ": unverified networked protected-content claim.")
        if not isinstance(flow["scopeNote"], str) or len(flow["scopeNote"].strip()) < 18:
            errors.append(fid + ": explicit limit missing.")
        paths = flow["evidencePaths"]
        if not isinstance(paths, list) or not paths or len(paths) != len(set(paths)):
            errors.append(fid + ": missing/duplicate flow evidence.")
        else:
            for p in paths:
                if p not in referenced_paths:
                    errors.append(fid + ": evidence not bound to a known component path: " + str(p))

    observations = data["sourceObservations"]
    observed = set()
    if not isinstance(observations, list) or not observations:
        return errors + ["Missing source blob observations."]
    for row in observations:
        if not isinstance(row, dict) or set(row) != OBSERVATION:
            errors.append("Malformed source observation.")
            continue
        path, sha = row["path"], row["blobSha"]
        if path not in referenced_paths or path in observed or not isinstance(sha, str) or re.fullmatch(r"[0-9a-f]{40}", sha) is None:
            errors.append("Invalid or duplicate observed Git blob: " + str(path))
        observed.add(path)
    if referenced_paths != observed:
        errors.append("Source observations must cover all referenced component files.")

    return errors


def main():
    try:
        inventory = json.loads((ROOT / INVENTORY).read_text())
        status = json.loads((ROOT / STATUS).read_text())
        errors = validate(inventory, ROOT, status)
    except (OSError, ValueError, TypeError) as e:
        errors = [str(e)]
    if errors:
        for item in errors:
            print("Invalid provisional E2EESA inventory: " + item, file=sys.stderr)
        return 1
    print("Provisional E2EESA inventory integrity verified. Review and conformance remain pending.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
