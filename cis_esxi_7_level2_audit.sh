#!/bin/bash
# CIS VMware ESXi 7.0 Benchmark Compliance Script - Level 2
# Includes Level 2-specific checks (Sections 1–2)

SUMMARY_LOG="/var/tmp/esxi7_cis_level2_summary.log"
> "$SUMMARY_LOG"

pass=0
fail=0
manual=0

report() {
  case "$1" in
    PASS) echo "[PASS] $2" | tee -a "$SUMMARY_LOG"; ((pass++));;
    FAIL) echo "[FAIL] $2" | tee -a "$SUMMARY_LOG"; ((fail++));;
    MANUAL) echo "[MANUAL] $2" | tee -a "$SUMMARY_LOG"; ((manual++));;
  esac
}

echo "Running CIS ESXi 7.0 Level 2 Audit (Sections 1-2)"
echo "================================================="

##########
# Section 1: Install
##########

# 1.4 Ensure the default value of individual salt per VM is configured
report MANUAL "1.4 Ensure the default value of individual salt per VM is configured"
echo '
This must be set via VM advanced setting:
  sched.mem.lpage.enable = "true"
  uuid.action = "create"
' >> "$SUMMARY_LOG"

##########
# Section 2: Communication
##########

# 2.4 Ensure default self-signed cert is not used
report MANUAL "2.4 Ensure default self-signed certificate is not used"
echo '
Verify using PowerCLI or the vSphere Client to inspect the certificate chain and install CA-signed certs:
  Get-VMHost | Get-VMHostCertificate | Select Thumbprint, NotAfter
' >> "$SUMMARY_LOG"

# 2.9 Ensure VDS health check is disabled
report MANUAL "2.9 Ensure VDS health check is disabled"
echo '
Use vSphere Web Client or PowerCLI:
  Get-VDSwitch | Get-VDPortgroup | Get-VDPortgroupTeamingPolicy | Select-Object HealthCheck
Ensure HealthCheck is disabled on all distributed switches.
' >> "$SUMMARY_LOG"


##########
# Section 5: Console
##########

# 5.6 Ensure Strict Lockdown mode is enabled
report MANUAL "5.6 Ensure Strict Lockdown mode is enabled"
echo '
From Host Client:
  1. Select host > Manage > Settings > Security Profile.
  2. Edit Lockdown Mode > Set to "Strict".
PowerCLI:
  Get-VMHost | Get-VMHostAdvancedConfiguration -Name "Config.HostAgent.plugins.hostsvc.esxAdminsGroup"
' >> "$SUMMARY_LOG"

# 5.7 Ensure SSH authorized_keys is empty
report MANUAL "5.7 Ensure the SSH authorized_keys file is empty"
echo '
Manually inspect each user directory for ~/.ssh/authorized_keys:
  find / -name authorized_keys
  cat ~/.ssh/authorized_keys
Ensure file is empty or not present.
' >> "$SUMMARY_LOG"

# 5.11 Ensure config files have not been modified
report MANUAL "5.11 Ensure contents of exposed configuration files have not been modified"
echo '
Review and validate integrity of configuration files:
  /etc/ssh/sshd_config
  /etc/vmware/esx.conf
  /etc/vmware/config
Compare against expected hash or baseline copies.
' >> "$SUMMARY_LOG"


##########
# Section 6: Storage
##########

# 6.2 Ensure the uniqueness of CHAP authentication secrets for iSCSI traffic
report MANUAL "6.2 Ensure CHAP secrets for iSCSI traffic are unique"
echo '
PowerCLI Command to List CHAP Names:
Get-VMHost | Get-VMHostHba | Where {$_.Type -eq "Iscsi"} | Select VMHost, Device, ChapType, @{N="CHAPName";E={$_.AuthenticationProperties.ChapName}}

Verify that all CHAP names are different across hosts/adapters.

Remediation:
1. Open vSphere Web Client > Host > Configure > Storage > Storage Adapters.
2. Select the iSCSI Adapter > Edit Authentication.
3. Use Bidirectional CHAP.
4. Ensure Outgoing and Incoming CHAP secrets are distinct and unique per host.
' >> "$SUMMARY_LOG"


##########
# Section 8: Virtual Machines
##########

# 8.5.1 Ensure VM limits are configured
report MANUAL "8.5.1 Ensure VM limits are configured"
echo '
PowerCLI:
Get-VM | Get-VMResourceConfiguration
Ensure reservations, shares, or resource pools are configured appropriately.
' >> "$SUMMARY_LOG"

# 8.5.2 Ensure hardware-based 3D acceleration is disabled
report MANUAL "8.5.2 Ensure 3D acceleration is disabled"
echo '
PowerCLI:
Get-VM | Get-AdvancedSetting -Name "mks.enable3d" | Select Entity, Name, Value
Expected: Value should be FALSE
' >> "$SUMMARY_LOG"

# 8.6.1 Ensure nonpersistent disks are limited
report MANUAL "8.6.1 Ensure nonpersistent disks are limited"
echo '
PowerCLI:
Get-VM | Get-HardDisk | Select Parent, Name, Filename, DiskType, Persistence
Ensure Persistence is not set to "Nonpersistent" unless explicitly required.
' >> "$SUMMARY_LOG"

# 8.7.2 Ensure host information is not sent to guests
report MANUAL "8.7.2 Ensure host information is not sent to guests"
echo '
PowerCLI:
Get-VM | Get-AdvancedSetting -Name "isolation.tools.getGuestInfo.disable" | Select Entity, Name, Value
Expected: Value should be TRUE
' >> "$SUMMARY_LOG"

echo ""
echo "=========== Level 2 Audit Summary ==========="
echo "Total PASSED : $pass"
echo "Total FAILED : $fail"
echo "Total MANUAL : $manual"
echo "Detailed log saved to $SUMMARY_LOG"
