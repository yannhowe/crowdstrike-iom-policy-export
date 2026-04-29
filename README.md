# Falcon IOM Policy Exporter

Export all CrowdStrike Falcon Cloud Security IOM (Indicator of Misconfiguration) policy definitions to CSV and JSON.

## What it does

Queries the Falcon CSPM API via `CSPMRegistration.get_policy_settings()` to retrieve every IOM policy definition across all cloud providers and exports to timestamped files.

## Output

| File | Format | Contents |
|------|--------|----------|
| `iom_policies_YYYY-MM-DD_HHMM.json` | JSON | Full API response with nested policy settings, benchmarks, FQL queries |
| `iom_policies_YYYY-MM-DD_HHMM.csv` | CSV | Flattened — one row per policy with serialized benchmarks |

### CSV columns

| Column | Description |
|--------|-------------|
| `policy_id` | Unique policy identifier |
| `name` | Policy name |
| `policy_type` | Type of policy |
| `cloud_provider` | `aws`, `azure`, `gcp`, or `kubernetes` |
| `cloud_service` | Cloud service (IAM, S3, EC2, etc.) |
| `cloud_service_subtype` | Service subcategory |
| `cloud_asset_type` | Asset type being evaluated |
| `default_severity` | `critical`, `high`, `medium`, or `informational` |
| `is_remediable` | Whether auto-remediation is supported |
| `cloud_friendly_service` | Human-readable service name |
| `cis_benchmark` | CIS benchmark mappings |
| `pci_benchmark` | PCI-DSS benchmark mappings |
| `nist_benchmark` | NIST benchmark mappings |
| `soc2_benchmark` | SOC 2 benchmark mappings |
| `hipaa_benchmark` | HIPAA benchmark mappings |
| `hitrust_benchmark` | HITRUST benchmark mappings |
| `iso_benchmark` | ISO 27001 benchmark mappings |
| `cisa_benchmark` | CISA benchmark mappings |
| `accounts_configured` | Number of accounts with custom settings |
| `fql_policy` | FQL query defining the policy logic |
| `remediation_summary` | Remediation guidance |
| `created_at` | Policy creation timestamp |
| `updated_at` | Last update timestamp |
| `policy_timestamp` | Policy evaluation timestamp |

## Requirements

- Python 3.8+
- [FalconPy](https://github.com/CrowdStrike/falconpy) SDK
- Falcon API credentials (environment variables or macOS Keychain)

### Install FalconPy

```bash
pip install crowdstrike-falconpy
```

## Setup

### Credentials

Credentials are resolved in this order:

#### Option 1: Environment variables (recommended for CI/CD and non-macOS)

```bash
export FALCON_CLIENT_ID=your_client_id
export FALCON_CLIENT_SECRET=your_client_secret
export FALCON_CLOUD_REGION=us-1  # optional, defaults to us-1
```

Supported regions: `us-1`, `us-2`, `eu-1`, `us-gov-1`

#### Option 2: macOS Keychain

```bash
security add-generic-password -s "falcon-client-id" -a "default" -w "YOUR_CLIENT_ID" -U
security add-generic-password -s "falcon-client-secret" -a "default" -w "YOUR_CLIENT_SECRET" -U
security add-generic-password -s "falcon-cloud-region" -a "default" -w "us-1" -U
```

Replace `default` with a profile name to support multiple CIDs. Set `FALCON_PROFILE=profile_name` to switch profiles.

### Required API Scope

`cspm-registration:read`

## Usage

```bash
python3 fetch_iom_policies.py
```

Output:
```
Profile: default
Region: us-1
Authenticating...
Fetching all IOM policies...
Retrieved 1712 policies (total: 1712)
JSON written: /tmp/iom_policies_2026-04-29_1708.json
CSV written: /tmp/iom_policies_2026-04-29_1708.csv

=== SUMMARY ===
Total policies: 1712

By cloud provider:
  aws: 797
  azure: 513
  gcp: 332
  kubernetes: 70

By default severity:
  critical: 26
  high: 305
  informational: 472
  medium: 909
```

## API Reference

| Endpoint | Operation | Purpose |
|----------|-----------|---------|
| `GET /settings/entities/policy/v1` | `GetCSPMPolicySettings` | List all policy settings |
| `GET /settings/entities/policy-details/v2` | `GetCSPMPoliciesDetails` | Batch fetch full details by ID |
| `GET /settings/entities/policy-details/v1` | `GetCSPMPolicy` | Single policy detail by ID |

Optional filters for `GetCSPMPolicySettings`:
- `cloud-platform` — `aws`, `azure`, `gcp`
- `service` — `IAM`, `S3`, `EC2`, `KMS`, etc.
- `policy-id` — specific policy ID (integer)

## License

MIT
