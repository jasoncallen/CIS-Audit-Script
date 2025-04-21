#!/bin/bash
# CIS VMware ESXi 8.0 Benchmark Audit Script (Level 1 and 2)
# Generated based on CIS Benchmark v1.2.0 - 2025-04-01
# Format: [PASS], [FAIL], [MANUAL]

SLOG="esxi8_audit_summary.log"
FRLOG="esxi8_failed.log"
MANLOG="esxi8_manual.log"
ELOG="esxi8_error.log"

> "$SLOG"
> "$FRLOG"
> "$MANLOG"
> "$ELOG"

log() {
    echo "$1" | tee -a "$SLOG"
}

fail() {
    echo "[FAIL] $1" | tee -a "$FRLOG"
}

manual() {
    echo "[MANUAL] $1" | tee -a "$MANLOG"
}

pass() {
    echo "[PASS] $1"
}

# ========== BEGIN CHECKS ==========

# ----------------------------------------------------------------------
# Section 1: Hardware
# ----------------------------------------------------------------------

manual "1.1 - Host hardware must have auditable, authentic, and up to date system & device firmware"
manual "1.2 - Host hardware must enable UEFI Secure Boot"
manual "1.3 - Host hardware must enable Intel TXT, if available"
manual "1.4 - Host hardware must enable and configure a TPM 2.0"
manual "1.5 - Host integrated hardware management controller must be secure"
manual "1.6 - Host integrated hardware management controller must enable time synchronization"
manual "1.7 - Host integrated hardware management controller must enable remote logging of events"




# Section 1: Hardware
log "Section 1: Hardware"

# 1.1 (L1) Host hardware must have auditable, authentic, and up to date system & device firmware (Manual)
manual "1.1 Ensure host hardware has auditable, authentic, and up-to-date firmware"

# 1.2 (L1) Host hardware must enable UEFI Secure Boot (Manual)
manual "1.2 Ensure UEFI Secure Boot is enabled on host hardware"

# 1.3 (L1) Host hardware must enable Intel TXT, if available (Manual)
manual "1.3 Ensure Intel TXT is enabled on host hardware if available"

# 1.4 (L1) Host hardware must enable and configure a TPM 2.0 (Manual)
manual "1.4 Ensure TPM 2.0 is enabled and configured on host hardware"

# 1.5 (L1) Host integrated hardware management controller must be secure (Manual)
manual "1.5 Ensure host integrated hardware management controller is secured"

# 1.6 (L1) Host integrated hardware management controller must enable time synchronization (Manual)
manual "1.6 Ensure time synchronization is enabled on integrated hardware management controller"

# 1.7 (L1) Host integrated hardware management controller must enable remote logging of events (Manual)
manual "1.7 Ensure remote logging is enabled on integrated hardware management controller"


# Section 2: Base
log "Section 2: Base"

# 2.1 (L1) Host must run software that has not reached End of General Support status (Manual)
manual "2.1 Ensure host software is still under General Support"

# 2.2 (L1) Host must have all software updates installed (Manual)
manual "2.2 Ensure all software updates are installed"

# 2.3 (L1) Host must enable Secure Boot enforcement (Manual)
manual "2.3 Ensure Secure Boot enforcement is enabled"

# 2.4 (L1) Host image profile acceptance level must be PartnerSupported or higher (Automated)
result=$(esxcli software acceptance get)
if [[ "$result" == "PartnerSupported" || "$result" == "VMwareCertified" ]]; then
    pass "2.4 Image profile acceptance level is set to $result"
else
    fail "2.4 Image profile acceptance level is $result (expected PartnerSupported or higher)"
fi

# 2.5 (L1) Host must only run binaries delivered via signed VIB (Manual)
manual "2.5 Ensure only signed VIBs are running"

# 2.6 (L1) Host must have reliable time synchronization sources (Automated)
ntp_sources=$(esxcli hardware clock get 2>&1)
if [[ $? -eq 0 && ! -z "$ntp_sources" ]]; then
    pass "2.6 Time synchronization source is configured"
else
    fail "2.6 No reliable time synchronization source found"
fi

# 2.7 (L1) Host must have time synchronization services enabled and running (Manual)
manual "2.7 Ensure time synchronization services are enabled and running"

# 2.8 (L1) Host must require TPM-based configuration encryption (Manual)
manual "2.8 Ensure TPM-based configuration encryption is required"

# 2.9 (L1) Host must not suppress warnings about unmitigated hyperthreading vulnerabilities (Manual)
manual "2.9 Ensure hyperthreading vulnerability warnings are not suppressed"

# 2.10 (L1) Host must restrict inter-VM transparent page sharing (Automated)
result=$(esxcli system settings advanced list -o Mem.ShareForceSalting | grep -i "Int Value" | awk '{print $NF}')
if [[ "$result" -eq 2 ]]; then
    pass "2.10 Inter-VM TPS is properly restricted"
else
    fail "2.10 Inter-VM TPS is not properly restricted (Mem.ShareForceSalting=$result)"
fi

# 2.11 (L1) Host must use sufficient entropy for cryptographic operations (Manual)
manual "2.11 Ensure host uses sufficient entropy for cryptographic operations"


# Section 3: Management
log "Section 3: Management"

# 3.1 (L1) Host should deactivate SSH (Automated)
ssh_status=$(esxcli network firewall ruleset list | grep -w "sshServer" | awk '{print $NF}')
if [[ "$ssh_status" == "false" ]]; then
    pass "3.1 SSH service is disabled"
else
    fail "3.1 SSH service is enabled"
fi

# 3.2 (L1) Host must deactivate the ESXi shell (Automated)
shell_status=$(esxcli system settings advanced list -o UserVars.ESXiShellEnabled | grep "Int Value" | awk '{print $NF}')
if [[ "$shell_status" -eq 0 ]]; then
    pass "3.2 ESXi shell is disabled"
else
    fail "3.2 ESXi shell is enabled (UserVars.ESXiShellEnabled=$shell_status)"
fi

# 3.3 (L1) Host must deactivate the ESXi Managed Object Browser (MOB) (Automated)
mob_status=$(esxcli system settings advanced list -o Config.HostAgent.plugins.solo.enableMob | grep "Int Value" | awk '{print $NF}')
if [[ "$mob_status" -eq 0 ]]; then
    pass "3.3 MOB is disabled"
else
    fail "3.3 MOB is enabled (enableMob=$mob_status)"
fi

# 3.4 (L1) Host must deactivate SLP (Manual)
manual "3.4 Ensure SLP is deactivated"

# 3.5 (L1) Host must deactivate CIM (Manual)
manual "3.5 Ensure CIM is deactivated"

# 3.6 (L1) Host should deactivate SNMP (Manual)
manual "3.6 Ensure SNMP is deactivated"

# 3.7 (L1) Host must automatically terminate idle DCUI sessions (Automated)
dcui_timeout=$(esxcli system settings advanced list -o UserVars.DcuiTimeOut | grep "Int Value" | awk '{print $NF}')
if [[ "$dcui_timeout" -le 600 ]]; then
    pass "3.7 DCUI timeout is set to $dcui_timeout seconds"
else
    fail "3.7 DCUI timeout exceeds recommended threshold (600s)"
fi

# 3.8 (L1) Host must automatically terminate idle shells (Automated)
shell_timeout=$(esxcli system settings advanced list -o UserVars.ESXiShellTimeOut | grep "Int Value" | awk '{print $NF}')
if [[ "$shell_timeout" -le 600 && "$shell_timeout" -ne 0 ]]; then
    pass "3.8 Shell timeout is configured correctly"
else
    fail "3.8 Shell timeout is either unset or too long (ESXiShellTimeOut=$shell_timeout)"
fi

# 3.9 (L1) Host must automatically deactivate shell services (Automated)
shell_interactive=$(esxcli system settings advanced list -o UserVars.ESXiShellInteractiveTimeOut | grep "Int Value" | awk '{print $NF}')
if [[ "$shell_interactive" -le 3600 && "$shell_interactive" -ne 0 ]]; then
    pass "3.9 Shell interactive timeout is configured properly"
else
    fail "3.9 Shell interactive timeout is not compliant (ESXiShellInteractiveTimeOut=$shell_interactive)"
fi

# 3.10 to 3.26 (L1) Various manual checks
manual "3.10 Ensure shell warning is not suppressed"
manual "3.11 Ensure password complexity is enforced"
manual "3.12 Ensure account lockout after failed login attempts is set"
manual "3.13 Ensure account unlock timeout is configured"
manual "3.14 Ensure password history is enforced"
manual "3.15 Ensure password maximum age is configured"
manual "3.16 Ensure API session timeout is configured"
manual "3.17 Ensure idle host client sessions are terminated"
manual "3.18 Ensure DCUI.Access list is accurate"
manual "3.19 Ensure Exception Users list is accurate"
manual "3.20 Ensure Normal Lockdown Mode is enabled"
manual "3.22 Ensure DCUI account shell access is denied"
manual "3.24 Ensure login banner is set for DCUI and Host Client"
manual "3.25 Ensure login banner is set for SSH"
manual "3.26 Ensure highest TLS version is enabled"


# Section 4: Logging
log "Section 4: Logging"

# 4.1 (L1) Host must configure a persistent log location for all locally stored system logs (Manual)
manual "4.1 Ensure persistent log location is configured for local system logs"

# 4.2 (L1) Host must transmit system logs to a remote log collector (Automated)
remote_log=$(esxcli system syslog config get | grep -i "Remote Host" | awk -F: '{print $2}' | xargs)
if [[ ! -z "$remote_log" ]]; then
    pass "4.2 Remote syslog server is configured: $remote_log"
else
    fail "4.2 No remote syslog server configured"
fi

# 4.3 (L1) Host must log sufficient information for events (Manual)
manual "4.3 Ensure logging captures sufficient event details"

# 4.4 (L1) Host must set the logging informational level to info (Manual)
manual "4.4 Ensure logging level is set to 'info'"

# 4.5 (L1) Host must deactivate log filtering (Manual)
manual "4.5 Ensure log filtering is disabled"

# 4.6 (L1) Host must enable audit record logging (Manual)
manual "4.6 Ensure audit logging is enabled"

# 4.7 (L1) Host must configure a persistent log location for all locally stored audit records (Manual)
manual "4.7 Ensure persistent log location is configured for audit records"

# 4.8 (L1) Host must store one week of audit records (Manual)
manual "4.8 Ensure audit records are retained for at least one week"

# 4.9 (L1) Host must transmit audit records to a remote log collector (Manual)
manual "4.9 Ensure audit records are sent to a remote log collector"

# 4.10 (L1) Host must verify certificates for TLS remote logging endpoints (Manual)
manual "4.10 Ensure TLS remote logging endpoints verify certificates"

# 4.11 (L1) Host must use strict x509 verification for TLS-enabled remote logging endpoints (Manual)
manual "4.11 Ensure strict x509 verification for TLS remote logging"


# Section 5: Network
log "Section 5: Network"

# 5.1 (L1) Host firewall must only allow traffic from authorized networks (Manual)
manual "5.1 Ensure firewall allows only authorized networks"

# 5.2 (L1) Host must block network traffic by default (Manual)
manual "5.2 Ensure default firewall policy blocks traffic"

# 5.3 (L1) Host must restrict use of the dvFilter network API (Manual)
manual "5.3 Ensure dvFilter API usage is restricted"

# 5.4 (L1) Host must filter Bridge Protocol Data Unit (BPDU) packets (Manual)
manual "5.4 Ensure BPDU packet filtering is configured"

# 5.6 (L1) Host should reject forged transmits on standard virtual switches and port groups (Automated)
forged_transmit=$(esxcli network vswitch standard policy security get -v vSwitch0 | grep "Forged Transmits" | awk '{print $NF}')
if [[ "$forged_transmit" == "false" ]]; then
    pass "5.6 Forged transmits are rejected on vSwitch0"
else
    fail "5.6 Forged transmits are allowed on vSwitch0"
fi

# 5.7 (L1) Host should reject MAC address changes on standard virtual switches and port groups (Automated)
mac_changes=$(esxcli network vswitch standard policy security get -v vSwitch0 | grep "MAC Address Changes" | awk '{print $NF}')
if [[ "$mac_changes" == "false" ]]; then
    pass "5.7 MAC address changes are rejected on vSwitch0"
else
    fail "5.7 MAC address changes are allowed on vSwitch0"
fi

# 5.8 (L1) Host should reject promiscuous mode requests on standard virtual switches and port groups (Automated)
promiscuous=$(esxcli network vswitch standard policy security get -v vSwitch0 | grep "Promiscuous Mode" | awk '{print $NF}')
if [[ "$promiscuous" == "false" ]]; then
    pass "5.8 Promiscuous mode is rejected on vSwitch0"
else
    fail "5.8 Promiscuous mode is enabled on vSwitch0"
fi

# 5.9 (L1) Host must restrict access to a default or native VLAN on standard virtual switches (Automated)
manual "5.9 Ensure access to default or native VLAN is restricted"

# 5.10 (L1) Host must restrict the use of Virtual Guest Tagging (VGT) on standard virtual switches (Automated)
manual "5.10 Ensure VGT use is restricted on standard virtual switches"

# 5.11 (L1) Host must isolate management communications (Manual)
manual "5.11 Ensure management communications are isolated"


# Section 6: Services
log "Section 6: Services"

# 6.1 (L1) Host must deactivate unused services (Manual)
manual "6.1 Ensure all unused services are disabled"

# 6.2 (L1) Host must deactivate DCUI if not used (Manual)
manual "6.2 Ensure DCUI is disabled if not used"

# 6.3 (L1) Host must deactivate SSH if not used (Automated)
ssh_running=$(esxcli network firewall ruleset list | grep -w "sshServer" | awk '{print $NF}')
if [[ "$ssh_running" == "false" ]]; then
    pass "6.3 SSH service is disabled"
else
    fail "6.3 SSH service is enabled"
fi

# 6.4 (L1) Host must deactivate ESXi Shell if not used (Automated)
shell_enabled=$(esxcli system settings advanced list -o UserVars.ESXiShellEnabled | grep "Int Value" | awk '{print $NF}')
if [[ "$shell_enabled" -eq 0 ]]; then
    pass "6.4 ESXi Shell is disabled"
else
    fail "6.4 ESXi Shell is enabled (UserVars.ESXiShellEnabled=$shell_enabled)"
fi

# 6.5 (L1) Host must deactivate vSphere Web Access if not used (Manual)
manual "6.5 Ensure vSphere Web Access is disabled if not used"

# 6.6 (L1) Host must deactivate SNMP if not used (Manual)
manual "6.6 Ensure SNMP service is disabled if not used"

# 6.7 (L1) Host must deactivate CIM if not used (Manual)
manual "6.7 Ensure CIM service is disabled if not used"

# 6.8 (L1) Host must deactivate SLP if not used (Manual)
manual "6.8 Ensure SLP service is disabled if not used"

# 6.9 (L1) Host must deactivate iSCSI if not used (Manual)
manual "6.9 Ensure iSCSI service is disabled if not used"

# 6.10 (L1) Host must deactivate NFS if not used (Manual)
manual "6.10 Ensure NFS service is disabled if not used"

# 6.11 (L1) Host must deactivate FTP if not used (Manual)
manual "6.11 Ensure FTP service is disabled if not used"

# 6.12 (L1) Host must deactivate TFTP if not used (Manual)
manual "6.12 Ensure TFTP service is disabled if not used"

# 6.13 (L1) Host must deactivate Web Services if not used (Manual)
manual "6.13 Ensure Web Services are disabled if not used"


# Section 7: Authentication
log "Section 7: Authentication"

# 7.1 (L1) Host must use Active Directory for local user authentication (Manual)
manual "7.1 Ensure Active Directory is used for local user authentication"

# 7.2 (L1) Host must not use default root account for interactive login (Manual)
manual "7.2 Ensure root account is not used for interactive login"

# 7.3 (L1) Host must use named accounts for all interactive logins (Manual)
manual "7.3 Ensure all interactive logins use named accounts"

# 7.4 (L1) Host must limit number of local users (Manual)
manual "7.4 Ensure the number of local users is limited"

# 7.5 (L1) Host must assign users to proper roles (Manual)
manual "7.5 Ensure users are assigned only appropriate roles"

# 7.6 (L1) Host must audit user account activity (Manual)
manual "7.6 Ensure user account activity is audited"


# Section 8: Users
log "Section 8: Users"

# 8.1 (L1) Host must use named accounts for all interactive logins (Manual)
manual "8.1 Ensure all interactive logins use named user accounts"

# 8.2 (L1) Host must assign unique roles to each named account (Manual)
manual "8.2 Ensure each named account is assigned a unique role"

# 8.3 (L1) Host must not assign administrator role to local accounts (Manual)
manual "8.3 Ensure local accounts are not assigned the Administrator role"

# 8.4 (L1) Host must remove unnecessary local user accounts (Manual)
manual "8.4 Ensure unnecessary local user accounts are removed"

# 8.5 (L1) Host must disable or remove the default ESXi user accounts (Manual)
manual "8.5 Ensure default ESXi user accounts are disabled or removed"


# Section 9: Virtual Machines
log "Section 9: Virtual Machines"

# 9.1 (L1) VM advanced settings must not expose host information (Automated)
manual "9.1 Ensure VM advanced settings do not expose host information"

# 9.2 (L1) VM must disable copy operations to the clipboard (Manual)
manual "9.2 Ensure copy operations to clipboard are disabled for VMs"

# 9.3 (L1) VM must disable paste operations from the clipboard (Manual)
manual "9.3 Ensure paste operations from clipboard are disabled for VMs"

# 9.4 (L1) VM must disable drag and drop operations (Manual)
manual "9.4 Ensure drag-and-drop operations are disabled for VMs"

# 9.5 (L1) VM must disable GUI interaction (Manual)
manual "9.5 Ensure GUI interaction is disabled for VMs"

# 9.6 (L1) VM must enable virtual printing only when required (Manual)
manual "9.6 Ensure virtual printing is disabled unless explicitly required"


# Section 10: Auditing
log "Section 10: Auditing"

# 10.1 (L1) Host must audit all administrative activity (Manual)
manual "10.1 Ensure all administrative activity is audited"

# 10.2 (L1) Host must audit all usage of privileged accounts (Manual)
manual "10.2 Ensure privileged account usage is audited"

# 10.3 (L1) Host must audit all security events (Manual)
manual "10.3 Ensure all security-related events are audited"

# 10.4 (L1) Host must audit all access to audit tools (Manual)
manual "10.4 Ensure access to audit tools is audited"

# ========== SUMMARY ==========
echo "" | tee -a "$SLOG"
echo " ---------------------------TOTALS----------------------------" | tee -a "$SLOG"
echo " - Total      - Total number of checks:          - $(($(grep -c '\[PASS\]' "$SLOG") + $(grep -c '\[FAIL\]' "$FRLOG") + $(grep -c '\[MANUAL\]' "$MANLOG")))" | tee -a "$SLOG"
echo " - Pass       - Recommendations passed:          - $(grep -c '\[PASS\]' "$SLOG")" | tee -a "$SLOG"
echo " - Fail       - Recommendations failed:          - $(grep -c '\[FAIL\]' "$FRLOG")" | tee -a "$SLOG"
echo " - Manual     - Recommendations manual review:   - $(grep -c '\[MANUAL\]' "$MANLOG")" | tee -a "$SLOG"

echo "Audit completed. Review $SLOG, $FRLOG, $MANLOG, and $ELOG for results."
