# CIS RHEL 9 Level 1 Audit Script

## Overview

This Bash script audits a Red Hat Enterprise Linux 9 (RHEL 9) system against the **CIS (Center for Internet Security) Level 1 Benchmark**. It checks for compliance across key security areas such as kernel module configurations, user account policies, cryptographic settings, file permissions, and system services.

The script is designed for **read-only auditing** and produces a report showing `[PASS]` or `[FAIL]` for each evaluated control. Each failure includes a human-readable explanation with clear emphasis on the non-compliant condition.

## Features

- Implements checks aligned with the [CIS RHEL 9 Benchmark v2.0.0 – Level 1](https://www.cisecurity.org/benchmark/red_hat_linux).
- Clean output with standardized `[PASS]` and `[FAIL]` messages.
- Results include:
  - Section headers (e.g., `1.1.1 – Disable unused filesystems`)
  - Per-check evaluation with failure reason
  - Count of total passes/fails
- Supports separation of failed checks into a dedicated fail report.
- Emphasized wording in failures for faster visual triage (`IS`, `NOT`, `HAVE`, `ONLY`, etc.)

## Usage

### 1. Clone or Download

```bash
git clone https://your.repo.url/cis-rhel9-audit.git
cd cis-rhel9-audit
```

### 2. Run the Script

```bash
sudo bash CIS_REHL_9_Audit.sh
```

> 🔐 **Note:** Root privileges (`sudo`) are required to access sensitive configuration and audit system-level permissions.

## Output

Two output files are generated in the same directory:

- `audit_report.txt`: Full output showing all `[PASS]` and `[FAIL]` results
- `fail_report.txt`: A filtered list of only `[FAIL]` entries for remediation tracking

## Example Output

```bash
[PASS]   SELinux mode IS set to enforcing in both runtime and config
[FAIL]   SSH MAC algorithms ARE weak or legacy (non-compliant)
[PASS]   Legacy kernel modules ARE NOT loaded
...
PASS count: 137
FAIL count: 12
```

## Structure

Each major CIS benchmark section is implemented as a distinct Bash function. The script uses a main loop to execute and report each check in logical order.

Function categories include:

- Filesystem configuration
- Software and service removal
- Network settings
- Logging and auditing
- User and authentication policies
- System integrity (e.g., AIDE, permissions)
- Kernel module status
- Firewall and SSH configurations

## Limitations

- The script performs **audit-only** checks; no remediations are applied automatically.
- It assumes a standard RHEL 9 layout and may require adaptation for heavily customized systems.
- Some GUI-specific checks (e.g., GNOME settings) may return false negatives on headless servers.

## Recommendations

- Run the script on non-production systems first to evaluate baseline compliance.
- Use the `fail_report.txt` output to drive remediation efforts manually or via automation tools (e.g., Ansible).
- Consider scheduling regular audits via cron for continuous compliance validation.

## License

This script is provided under the [MIT License](LICENSE). It is intended for internal security assessments and learning purposes.

## Author

- Maintained by: Jason Callen
- Contact: [your-email@example.com]

## Contributions

Pull requests, suggestions, and benchmark-specific improvements are welcome.
