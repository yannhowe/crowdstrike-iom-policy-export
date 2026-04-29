#!/usr/bin/env python3
"""Fetch all IOM policies from Falcon CSPM and export to CSV + JSON."""

import sys
import os
import json
import csv
import subprocess
from datetime import datetime
from typing import Optional

try:
    from falconpy import CSPMRegistration
except ImportError:
    print("FalconPy SDK not found. Install with: pip install crowdstrike-falconpy")
    sys.exit(1)


def get_falcon_profile() -> str:
    profile = os.getenv('FALCON_PROFILE')
    if profile:
        return profile
    # Check for active CID profile in project memory
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
    for path in [os.path.join(project_root, '.claude', 'memory', 'active-cid.txt'),
                 os.path.expanduser('~/.claude/memory/active-cid.txt')]:
        try:
            with open(path) as f:
                for line in f:
                    if line.startswith('profile='):
                        return line.strip().split('=', 1)[1]
        except FileNotFoundError:
            continue
    return 'default'


def get_keychain_password(service: str, account: str, profile: Optional[str] = None) -> Optional[str]:
    if profile is None:
        profile = get_falcon_profile()
    try:
        result = subprocess.run(['security', 'find-generic-password', '-s', service, '-a', profile, '-w'],
                              capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        pass
    if profile == 'default':
        try:
            result = subprocess.run(['security', 'find-generic-password', '-s', 'crowdstrike-falcon-api', '-a', account, '-w'],
                                  capture_output=True, text=True, check=True)
            return result.stdout.strip()
        except subprocess.CalledProcessError:
            pass
    return None


def main():
    profile = get_falcon_profile()
    print(f"Profile: {profile}")

    client_id = get_keychain_password("falcon-client-id", "client-id", profile)
    client_secret = get_keychain_password("falcon-client-secret", "client-secret", profile)
    region = get_keychain_password("falcon-cloud-region", "region", profile)

    if not client_id or not client_secret:
        print(f"Credentials not found for profile: {profile}")
        sys.exit(1)

    base_url = "https://api.crowdstrike.com"
    if region and region != "us-1":
        base_url = f"https://api.{region}.crowdstrike.com"

    print(f"Region: {region or 'us-1'}")
    print("Authenticating...")

    falcon = CSPMRegistration(client_id=client_id, client_secret=client_secret, base_url=base_url)

    # Fetch all policies (no filters)
    print("Fetching all IOM policies...")
    response = falcon.get_policy_settings()

    if response["status_code"] != 200:
        print(f"API error: {response['status_code']}")
        print(json.dumps(response["body"], indent=2))
        sys.exit(1)

    policies = response["body"]["resources"]
    total = response["body"]["meta"]["pagination"]["total"] if "pagination" in response["body"].get("meta", {}) else len(policies)
    print(f"Retrieved {len(policies)} policies (total: {total})")

    if not policies:
        print("No policies returned.")
        sys.exit(0)

    # --- JSON output ---
    ts = datetime.now().strftime("%Y-%m-%d_%H%M")
    json_path = f"/tmp/iom_policies_{ts}.json"
    with open(json_path, "w") as f:
        json.dump(policies, f, indent=2, default=str)
    print(f"JSON written: {json_path}")

    # --- CSV output ---
    # Flatten policies for CSV - extract key fields, serialize nested objects
    csv_path = f"/tmp/iom_policies_{ts}.csv"
    csv_rows = []
    for p in policies:
        row = {
            "policy_id": p.get("policy_id", ""),
            "name": p.get("name", ""),
            "policy_type": p.get("policy_type", ""),
            "cloud_provider": p.get("cloud_provider", ""),
            "cloud_service": p.get("cloud_service", ""),
            "cloud_service_subtype": p.get("cloud_service_subtype", ""),
            "cloud_asset_type": p.get("cloud_asset_type", ""),
            "default_severity": p.get("default_severity", ""),
            "is_remediable": p.get("is_remediable", ""),
            "cloud_friendly_service": p.get("cloud_friendly_service", ""),
        }

        # Flatten benchmarks
        for bm_name in ["cis_benchmark", "pci_benchmark", "nist_benchmark", "soc2_benchmark",
                         "hipaa_benchmark", "hitrust_benchmark", "iso_benchmark", "cisa_benchmark"]:
            benchmarks = p.get(bm_name, [])
            if benchmarks:
                row[bm_name] = "; ".join(
                    f"{b.get('benchmark_short', '')} ({b.get('recommendation_number', '')})"
                    for b in benchmarks
                )
            else:
                row[bm_name] = ""

        # Count policy_settings entries
        settings = p.get("policy_settings", [])
        row["accounts_configured"] = len(settings) if settings else 0

        row["fql_policy"] = p.get("fql_policy", "")
        row["remediation_summary"] = p.get("remediation_summary", "")
        row["created_at"] = p.get("created_at", "")
        row["updated_at"] = p.get("updated_at", "")
        row["policy_timestamp"] = p.get("policy_timestamp", "")

        csv_rows.append(row)

    if csv_rows:
        fieldnames = list(csv_rows[0].keys())
        with open(csv_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(csv_rows)
        print(f"CSV written: {csv_path}")

    # Summary
    providers = {}
    severities = {}
    for p in policies:
        cp = p.get("cloud_provider", "unknown")
        providers[cp] = providers.get(cp, 0) + 1
        sev = p.get("default_severity", "unknown")
        severities[sev] = severities.get(sev, 0) + 1

    print(f"\n=== SUMMARY ===")
    print(f"Total policies: {len(policies)}")
    print(f"\nBy cloud provider:")
    for k, v in sorted(providers.items()):
        print(f"  {k}: {v}")
    print(f"\nBy default severity:")
    for k, v in sorted(severities.items()):
        print(f"  {k}: {v}")


if __name__ == "__main__":
    main()
