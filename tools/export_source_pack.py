"""Export the immutable legacy detector registry as a declarative source pack."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
from src.patterns import DEFAULT_CONTEXT_RULES, DEFAULT_DETECTION_RULES

SOURCE_LOCK = "66924ea"

RULE_PROVENANCE = {
    "CRT-SEC-180": {
        "source": "Paddle Developer Docs — API key format",
        "url": "https://developer.paddle.com/api-reference/about/authentication/",
        "license": "vendor-documentation",
    },
}


def provenance_for(rule_id: str) -> dict:
    provenance = RULE_PROVENANCE.get(rule_id, {
        "source": "CodeRiskTools legacy detection registry",
        "url": "https://coderisktools.invalid/source-registry",
        "license": "project-policy",
    }).copy()
    provenance["source_lock"] = SOURCE_LOCK
    return provenance


def build_pack() -> dict:
    rules = []
    for rule in DEFAULT_DETECTION_RULES:
        rules.append({
            "name": rule.name,
            "regex": rule.regex,
            "severity": rule.severity,
            "description": rule.description,
            "rule_id": rule.rule_id,
            "category": rule.category,
            "confidence": rule.confidence,
            "remediation": rule.remediation,
            "kind": rule.kind,
            "file_globs": list(rule.file_globs),
            "provenance": provenance_for(rule.rule_id),
        })
    context_rules = []
    for rule in DEFAULT_CONTEXT_RULES:
        context_rules.append({
            "name": rule.name,
            "required_regexes": list(rule.required_regexes),
            "max_line_span": rule.max_line_span,
            "severity": rule.severity,
            "description": rule.description,
            "rule_id": rule.rule_id,
            "category": rule.category,
            "confidence": rule.confidence,
            "remediation": rule.remediation,
            "kind": rule.kind,
            "file_globs": list(rule.file_globs),
            "provenance": provenance_for(rule.rule_id),
        })
    return {
        "schema": "coderisktools.rule-source-pack",
        "version": 2,
        "source_commit": SOURCE_LOCK,
        "detector_count": len(rules) + len(context_rules),
        "rules": rules,
        "context_rules": context_rules,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(build_pack(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
