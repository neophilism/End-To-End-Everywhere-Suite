#!/usr/bin/env python3
"""Pinned E2EESA registry compatibility checks; not a conformance certification."""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


def public_string_constant(source: str, name: str) -> str | None:
    pattern = rf'(?m)^pub const {re.escape(name)}: &str = "([^"]+)";$'
    matches = re.findall(pattern, source)
    return matches[0] if len(matches) == 1 else None


def check_bindings(
    pin: dict, catalog: dict, algorithms: dict,
    keystore_source: str, message_source: str, observed_commit: str
) -> list[str]:
    errors: list[str] = []
    if observed_commit != pin.get("source_commit"):
        errors.append("standard source commit does not match the reviewed pin")
    if catalog.get("profiles") is None or not isinstance(catalog["profiles"], list):
        return errors + ["standards profile catalog is missing the profiles array"]
    if not isinstance(algorithms.get("suites"), list):
        return errors + ["standards algorithm registry is missing the suites array"]
    if pin.get("status") != "compatibility-inventory-only":
        errors.append("binding inventory must explicitly disclaim certification")

    profiles = {
        (p.get("profile_id"), p.get("profile_version")): p
        for p in catalog["profiles"] if isinstance(p, dict)
    }
    for symbol, expected in pin.get("key_storage_constants", {}).items():
        actual = public_string_constant(keystore_source, symbol)
        if actual != expected:
            errors.append(f"{symbol}: implementation {actual!r} != pinned {expected!r}")
        if not isinstance(expected, str) or expected.count("@") != 1:
            errors.append(f"{symbol}: profile reference must be exact name@version")
            continue
        name, version = expected.split("@")
        profile = profiles.get((name, version))
        if profile is None:
            errors.append(f"{symbol}: pinned profile absent from catalog")
        elif profile.get("family_id") != "secret-storage" or profile.get("status") not in ("allowed", "recommended"):
            errors.append(f"{symbol}: profile family/status is not approved for use")

    suite_entry = pin.get("message_suite_constant", {})
    suite_symbol = suite_entry.get("symbol")
    suite_id = suite_entry.get("value")
    if not isinstance(suite_symbol, str) or not isinstance(suite_id, str):
        errors.append("message suite symbol/id missing")
    else:
        actual_suite = public_string_constant(message_source, suite_symbol)
        if actual_suite != suite_id:
            errors.append(f"{suite_symbol}: implementation {actual_suite!r} != pinned {suite_id!r}")
        suites = [s for s in algorithms["suites"] if isinstance(s, dict) and s.get("id") == suite_id]
        if len(suites) != 1 or suites[0].get("status") not in ("allowed", "recommended"):
            errors.append("message suite is absent, ambiguous, or not allowed in pinned registry")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--standard-root", required=True, type=Path)
    parser.add_argument("--suite-root", default=Path("."), type=Path)
    args = parser.parse_args()
    standard = args.standard_root.resolve()
    suite = args.suite_root.resolve()
    pin = json.loads((suite / ".e2eesa" / "binding-pin.json").read_text(encoding="utf-8"))
    observed = subprocess.check_output(
        ["git", "-C", str(standard), "rev-parse", "HEAD"], text=True
    ).strip()
    catalog = json.loads((standard / "profiles/catalog.json").read_text(encoding="utf-8"))
    registry = json.loads((standard / "registry/cryptographic-algorithms.json").read_text(encoding="utf-8"))
    errors = check_bindings(
        pin, catalog, registry,
        (suite / "crates/e2ee-keystore/src/lib.rs").read_text(encoding="utf-8"),
        (suite / "crates/e2ee-message/src/lib.rs").read_text(encoding="utf-8"),
        observed,
    )
    if errors:
        for error in errors:
            print(f"E2EESA BINDING ERROR: {error}", file=sys.stderr)
        return 1
    print(f"Registry inventory verified at {observed[:12]}; no conformance claim.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
