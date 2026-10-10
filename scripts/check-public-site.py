#!/usr/bin/env python3
"""Fail the static-site build rather than misrepresenting Suite readiness."""
import json
from html.parser import HTMLParser
from pathlib import Path

root = Path(__file__).resolve().parents[1] / "site/public"
status = json.loads((root / "status.json").read_text(encoding="utf-8"))
assert status["site_type"] == "static-informational"
assert status["product_maturity"] == "pre-alpha"
for key in ("is_encryption_service", "production_ready", "independently_certified"):
    assert status[key] is False, f"Public site status must not claim {key}"
html = (root / "index.html").read_text(encoding="utf-8")
assert "not an encryption service" in html.lower()
assert "not independently certified" in html.lower()
assert "not yet available" in html.lower()
assert "stylesheet" in html
assert (root / "styles.css").is_file()

class DocumentCheck(HTMLParser):
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in ("script", "iframe", "form", "object", "embed"):
            raise ValueError("Informational site must not load scripts, iframe, forms or plugins")
        for key in ("src", "href"):
            value = attrs.get(key, "")
            if value.lower().startswith(("javascript:", "data:", "http:")):
                raise ValueError(f"Unsupported URL form in {tag}: {value}")

parser = DocumentCheck()
parser.feed(html)
print("Static informational site verified: no production security claims.")
