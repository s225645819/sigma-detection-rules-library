# Sigma Detection Rules Library

A production-grade library of custom Sigma detection rules for multi-SIEM deployment (Splunk, Microsoft Sentinel, Elastic).

## Overview

This repository contains **15 custom detection rules** targeting real-world attack techniques, mapped to the **MITRE ATT&CK framework**, and automatically converted to multiple SIEM query languages via a GitHub Actions CI/CD pipeline.

### Key Features

- **SIEM-Agnostic:** One rule = Splunk SPL + Sentinel KQL + Elastic ECS output.
- **Detection-as-Code:** Fully automated CI/CD pipeline using GitHub Actions.
- **Unit Tested:** Every rule is programmatically validated for YAML syntax, required fields, unique UUIDs, and MITRE mappings.
- **Behavior-Focused:** Rules target adversarial behaviors (TTPs) rather than static indicators (IoCs).

---

## Detection Coverage

| Rule Focus | Target Binary / Process | MITRE ATT&CK |
|---|---|---|
| **Cobalt Strike Beacon Execution** | `rundll32.exe`, `powershell.exe` | T1059.001, T1071 |
| **Mimikatz LSASS Dump** | `mimikatz.exe`, `mimidrv.sys` | T1003.001 |
| **PsExec Lateral Movement** | `psexec.exe`, `services.exe` | T1021.002 |
| **Web Shell Upload** | HTTP POST (`.aspx`, `.jsp`, `.php`) | T1505.003 |
| **PowerShell Download & Execute** | `powershell.exe` (IEX, DownloadString) | T1059.001 |
| **Macro/Office Execution** | `WINWORD.EXE` → `cmd.exe` | T1203 |
| **Registry Run Key Persistence** | HKCU/HKLM Run Keys | T1547.001 |
| **Process Injection** | `svchost.exe` → `cmd.exe` | T1055 |
| **Scheduled Task Persistence** | `schtasks.exe` | T1053.005 |
| **UAC Bypass / PrivEsc** | `fodhelper.exe`, `eventvwr.exe` | T1547 |
| **OAuth Token Theft** | Azure AD Consent | T1528 |
| **DNS Exfiltration** | DNS TXT Records | T1041 |
| **Linux Reverse Shell** | `bash`, `nc` | T1059.004, T1071 |
| **Kerberoasting Ticket Request** | Windows Security Event 4769 (RC4) | T1558.003 |
| **Suspicious ACL Modification** | `icacls.exe`, `cacls.exe` | T1222.001 |

---

## CI/CD Pipeline Architecture

This repository treats detection rules as code. Every push to the `main` branch triggers a GitHub Actions workflow that performs the following:

1. **Syntax Validation:** Verifies YAML structure using `sigma check`.
2. **Unit Testing:** Runs a Python/PyTest script (`tests/test_sigma_rules.py`) to ensure all rules have required metadata, unique IDs, and MITRE tags.
3. **Automated Conversion:** Uses `sigma-cli` to compile the YAML rules into:
   - **Splunk SPL**
   - **Sentinel KQL**
   - **Elastic ECS**
4. **Artifact Generation:** Packages the converted queries into a downloadable artifact.

See `.github/workflows/validate-sigma.yml` for pipeline details.

---

## How to Use

### Converting Sigma to Your SIEM

**Splunk SPL:**
```bash
sigma convert -t splunk rules/windows/process_creation/proc_creation_cobalt_strike_beacon.yml
```

**Sentinel KQL:**
```bash
sigma convert -t azure_sentinel rules/windows/process_creation/proc_creation_cobalt_strike_beacon.yml
```

**Elastic ECS:**
```bash
sigma convert -t elastic-ecs rules/windows/process_creation/proc_creation_cobalt_strike_beacon.yml
```

### Deploying to Your SIEM

**Sentinel:** Copy converted KQL → Analytics Rules → Create new rule → Paste query

**Splunk:** Copy converted SPL → Search & Reporting → Create saved search

**Elastic:** Copy converted query → Kibana → Create detection rule

---
## Local Development & Testing

To run the testing suite locally:

```bash
# Install dependencies
pip install -r requirements.txt

# Run unit tests
python -m pytest tests/ -v

---

## Rule Format

All rules follow Sigma standard YAML format:

```yaml
title: Rule Title
id: [UUID]
status: experimental|test|stable
description: What this rule detects
logsource:
  category: process_creation|registry_event|network_connection
  product: windows|linux|generic
detection:
  selection:
    Image|endswith: powershell.exe
    CommandLine|contains:
      - '-enc'
      - 'IEX'
  condition: selection
falsepositives:
  - Legitimate tool X
level: low|medium|high|critical
mitre:
  - attack.execution
  - attack.t1059.001
```

## References

- Sigma Rule Documentation: https://sigma.readthedocs.io/
- SigmaHQ GitHub: https://github.com/SigmaHQ/sigma
- Sigma Converter (sigmac): https://github.com/SigmaHQ/pySigma
- MITRE ATT&CK: https://attack.mitre.org/
