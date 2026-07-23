#!/usr/bin/env python3
"""Build a bounded real seed database from verified cache plus OSV API queries."""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path
from urllib.error import HTTPError

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from src.vulnerability.seed import SEED_ECOSYSTEMS, build_seed_database


PACKAGE_PROBES = (
    ("PyPI", "django", "2.2.0"),
    ("npm", "lodash", "4.17.15"),
    ("Go", "github.com/golang-jwt/jwt/v4", "4.0.0"),
    ("crates.io", "time", "0.1.44"),
    ("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1"),
    ("NuGet", "System.Text.Encodings.Web", "4.7.0"),
    ("Packagist", "symfony/http-foundation", "5.4.0"),
)


def _query_package(ecosystem: str, package: str, version: str) -> list[str]:
    payload = json.dumps({"package": {"ecosystem": ecosystem, "name": package}, "version": version}).encode("utf-8")
    request = urllib.request.Request("https://api.osv.dev/v1/query", data=payload, headers={"Accept": "application/json", "Content-Type": "application/json", "User-Agent": "coderisktools-seed/1"}, method="POST")
    with urllib.request.urlopen(request, timeout=30) as response:
        value = json.loads(response.read().decode("utf-8"))
    return [item["id"] for item in value.get("vulns", []) if isinstance(item, dict) and isinstance(item.get("id"), str)]


def _fetch_epss(cves: list[str]) -> dict:
    if not cves:
        return {"data": []}
    query = ",".join(cves[:1000])
    request = urllib.request.Request(
        "https://api.first.org/data/v1/epss?cve=" + urllib.parse.quote(query),
        headers={"Accept": "application/json", "User-Agent": "coderisktools-seed/1"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        value = json.loads(response.read().decode("utf-8"))
    return value if isinstance(value, dict) else {"data": []}


def _cache_with_targeted_epss(cache: Path, records_by_ecosystem: dict[str, list[dict]]) -> Path:
    temporary = Path(tempfile.mkdtemp(prefix="coderisktools-seed-cache-"))
    for filename in ("cisa-kev.json", "github-advisories.json"):
        shutil.copy2(cache / filename, temporary / filename)
    cves = sorted({alias for records in records_by_ecosystem.values() for record in records for alias in record.get("aliases", []) if isinstance(alias, str) and alias.startswith("CVE-")})
    (temporary / "epss.json").write_text(json.dumps(_fetch_epss(cves), sort_keys=True), encoding="utf-8")
    return temporary


def _fetch_vulnerability(cve: str) -> dict | None:
    request = urllib.request.Request(
        f"https://api.osv.dev/v1/vulns/{cve}",
        headers={"Accept": "application/json", "User-Agent": "coderisktools-seed/1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            value = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        if exc.code == 404:
            return None
        raise
    return value if isinstance(value, dict) else None


def _post_querybatch(cves: list[str]) -> list[dict]:
    payload = json.dumps({"queries": [{"query": cve} for cve in cves]}).encode("utf-8")
    request = urllib.request.Request(
        "https://api.osv.dev/v1/querybatch",
        data=payload,
        headers={"Accept": "application/json", "Content-Type": "application/json", "User-Agent": "coderisktools-seed/1"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        body = json.loads(response.read().decode("utf-8"))
    records: list[dict] = []
    for result in body.get("results", []):
        for vulnerability in result.get("vulns", []):
            if isinstance(vulnerability, dict) and isinstance(vulnerability.get("id"), str):
                records.append(vulnerability)
    return records


def _cache_cves(cache: Path, limit: int) -> list[str]:
    cves: list[str] = []
    for filename in ("cisa-kev.json", "github-advisories.json"):
        payload = json.loads((cache / filename).read_text(encoding="utf-8"))
        records = payload.get("vulnerabilities", []) if isinstance(payload, dict) else payload
        for record in records:
            if filename.startswith("cisa"):
                value = record.get("cveID")
            else:
                value = record.get("cve_id")
            if isinstance(value, str) and value.startswith("CVE-") and value not in cves:
                cves.append(value)
            if len(cves) >= limit:
                return cves
    return cves


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cache", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--max-records-per-ecosystem", type=int, default=500)
    parser.add_argument("--max-cves", type=int, default=500)
    args = parser.parse_args()
    cache = Path(args.cache)
    cves = _cache_cves(cache, args.max_cves)
    if not cves:
        raise SystemExit("verified cache contains no CVE identifiers")
    records_by_ecosystem = {ecosystem: [] for ecosystem in SEED_ECOSYSTEMS}
    seen_ids: set[str] = set()
    for ecosystem, package, version in PACKAGE_PROBES:
        for identifier in _query_package(ecosystem, package, version):
            if identifier in seen_ids:
                continue
            record = _fetch_vulnerability(identifier)
            if record:
                records_by_ecosystem[ecosystem].append(record)
                seen_ids.add(identifier)
    for cve in cves:
        record = _fetch_vulnerability(cve)
        if not record:
            continue
        ecosystems = {affected.get("package", {}).get("ecosystem") for affected in record.get("affected", []) if isinstance(affected, dict)}
        for ecosystem in ecosystems & set(SEED_ECOSYSTEMS):
            if len(records_by_ecosystem[ecosystem]) < args.max_records_per_ecosystem:
                records_by_ecosystem[ecosystem].append(record)
    targeted_cache = _cache_with_targeted_epss(cache, records_by_ecosystem)
    try:
        manifest = build_seed_database(targeted_cache, args.output, records_by_ecosystem, max_records_per_ecosystem=args.max_records_per_ecosystem)
    finally:
        shutil.rmtree(targeted_cache, ignore_errors=True)
    print(json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
