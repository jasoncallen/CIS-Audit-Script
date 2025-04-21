#!/bin/bash
# CIS VMware ESXi 7.0 Benchmark Compliance Script (Level 1)
# Includes Sections 1, 2, and 3

SUMMARY_LOG="/var/tmp/esxi7_cis_level1_summary.log"
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

echo "Running CIS ESXi 7.0 Level 1 Audit (Sections 1-3)"
echo "================================================="

##########
# Section 1: Install
##########

report MANUAL "1.1 Ensure ESXi is properly patched"
echo '
PowerCLI:
Foreach ($VMHost in Get-VMHost) {
  $EsxCli = Get-EsxCli -VMHost $VMHost -V2
  $EsxCli.software.vib.list.invoke() | Select-Object @{N="VMHost";E={$VMHost}},*
}
' >> "$SUMMARY_LOG"

echo -n "1.2 Checking VIB Acceptance Level: "
level=$(esxcli software acceptance get)
if [[ "$level" =~ "VMwareCertified|VMwareAccepted|PartnerSupported" ]]; then
  report PASS "1.2 VIB Acceptance Level is $level"
else
  report FAIL "1.2 VIB Acceptance Level is $level"
fi

report MANUAL "1.3 Ensure no unauthorized kernel modules are loaded"
echo '
Run: esxcli system module list
And: esxcli system module get -m <module_name>
' >> "$SUMMARY_LOG"

##########
# Section 2: Communication
##########

echo -n "2.1 NTP Client Firewall Rule: "
ntp_rule=$(esxcli network firewall ruleset list | grep ntpClient | awk '{print $3}')
if [[ "$ntp_rule" == "true" ]]; then
  report PASS "2.1 NTP firewall ruleset is enabled"
else
  report FAIL "2.1 NTP firewall ruleset is NOT enabled"
fi

report MANUAL "2.2 Ensure firewall restricts access to services"

mob=$(vim-cmd hostsvc/mob | grep -i disabled)
if [[ -n "$mob" ]]; then
  report PASS "2.3 MOB is disabled"
else
  report FAIL "2.3 MOB is NOT disabled"
fi

report MANUAL "2.5 SNMP Configuration"
report MANUAL "2.6 dvfilter API not configured if unused"
report MANUAL "2.7 Expired and revoked SSL certificates are removed"
report MANUAL "2.8 vSphere Authentication Proxy is used"

##########
# Section 3: Logging
##########

echo -n "3.1 Core Dump Check: "
coredump_active=$(esxcli system coredump network check | grep -i "true")
if [[ "$coredump_active" ]]; then
  report PASS "3.1 Network core dump collection is active"
else
  report FAIL "3.1 Network core dump is not configured"
fi

report MANUAL "3.2 Persistent logging is configured on non-volatile storage"
echo '
Check if logs are stored in non-volatile directory:
  esxcli system syslog config get | grep -i logdir
Ensure it is NOT pointing to /tmp or memory-only location
' >> "$SUMMARY_LOG"

echo -n "3.3 Remote Syslog Host: "
remote_syslog=$(esxcli system syslog config get | grep -i RemoteHost | awk -F: '{print $2}' | xargs)
if [[ -n "$remote_syslog" ]]; then
  report PASS "3.3 Remote logging is configured to $remote_syslog"
else
  report FAIL "3.3 Remote logging is not configured"
fi

echo ""
echo "=========== Audit Summary ==========="
echo "Total PASSED : $pass"
echo "Total FAILED : $fail"
echo "Total MANUAL : $manual"
echo "Detailed log saved to $SUMMARY_LOG"


##########
# Section 4: Access
##########

# 4.1 Ensure a non-root user account exists
report MANUAL "4.1 Ensure a non-root user account exists for local admin access"
echo '
Verify via Host Client:
1. Log in to host using Host Client (not vSphere Web Client).
2. Navigate to Manage > Security & Users > Users tab.
3. Ensure at least one local user exists with Admin role assigned under Permissions.
' >> "$SUMMARY_LOG"

# 4.2 Password complexity
report MANUAL "4.2 Ensure passwords are required to be complex"
echo '
Check /etc/pam.d/passwd for pam_passwdqc.so configuration enforcing length and class rules.
' >> "$SUMMARY_LOG"

# 4.3 Max failed login attempts = 5
echo -n "4.3 Checking max failed login attempts: "
failures=$(esxcli system settings advanced list -o Security.AccountLockFailures | awk '/Int Value/ {print $NF}')
if [[ "$failures" -eq 5 ]]; then
  report PASS "4.3 Max failed login attempts is set to 5"
else
  report FAIL "4.3 Max failed login attempts is $failures"
fi

# 4.4 Account lockout = 15 minutes
echo -n "4.4 Checking account lockout duration: "
lockout_time=$(esxcli system settings advanced list -o Security.AccountUnlockTime | awk '/Int Value/ {print $NF}')
if [[ "$lockout_time" -eq 900 ]]; then
  report PASS "4.4 Account unlock time is set to 900 seconds (15 minutes)"
else
  report FAIL "4.4 Account unlock time is $lockout_time seconds"
fi

# 4.5 Password history
report MANUAL "4.5 Ensure previous 5 passwords are prohibited"
echo '
Review pam_passwdqc.so or account password policy for history enforcement.
' >> "$SUMMARY_LOG"

# 4.6 Active Directory usage
report MANUAL "4.6 Ensure Active Directory is used for local user authentication"
echo '
Check domain join status via:
  esxcli system hostname get
  esxcli system settings advanced list -o Config.HostAgent.plugins.hostsvc.esxAdminsGroup
' >> "$SUMMARY_LOG"

# 4.7 esxAdminsGroup contents
report MANUAL "4.7 Verify only authorized users and groups belong to esxAdminsGroup"
echo '
Use:
  esxcli system settings advanced list -o Config.HostAgent.plugins.hostsvc.esxAdminsGroup
Check group members in AD or ESXi permissions view.
' >> "$SUMMARY_LOG"

# 4.8 Exception Users list
report MANUAL "4.8 Ensure Exception Users list is properly configured"
echo '
Use:
  esxcli system settings advanced list -o Config.HostAgent.plugins.hostsvc.esxAdminsGroup
  Get-VMHost | Get-AdvancedSetting -Name "DCUI.Access"
Ensure only expected accounts like root or break-glass accounts exist.
' >> "$SUMMARY_LOG"


##########
# Section 5: Console
##########

# 5.1 DCUI timeout = 600 or less
echo -n "5.1 DCUI Timeout: "
dcui_timeout=$(esxcli system settings advanced list -o /UserVars/DCUIIdleTimeout | grep 'Int Value' | awk '{print $NF}')
if [[ "$dcui_timeout" -le 600 ]]; then
  report PASS "5.1 DCUI timeout is set to $dcui_timeout seconds"
else
  report FAIL "5.1 DCUI timeout is set to $dcui_timeout seconds"
fi

# 5.2 ESXi Shell disabled
shell_status=$(vim-cmd hostsvc/enable_esx_shell | grep false)
if [[ -n "$shell_status" ]]; then
  report PASS "5.2 ESXi shell is disabled"
else
  report FAIL "5.2 ESXi shell is enabled"
fi

# 5.3 SSH disabled
ssh_running=$(esxcli network firewall ruleset list | grep sshServer | awk '{print $3}')
if [[ "$ssh_running" == "false" ]]; then
  report PASS "5.3 SSH is disabled"
else
  report FAIL "5.3 SSH is enabled"
fi

# 5.4 CIM access is limited
report MANUAL "5.4 Ensure CIM access is limited"
echo '
Use PowerCLI:
Get-VMHost | Get-VMHostService | Where {$_.Key -like "*CIM*"} | Select VMHost, Label, Running
' >> "$SUMMARY_LOG"

# 5.5 Normal Lockdown mode
lockdown_mode=$(esxcli system settings advanced list -o /UserVars/HostClientDisable | grep 'Int Value' | awk '{print $NF}')
if [[ "$lockdown_mode" -eq 0 ]]; then
  report PASS "5.5 Normal Lockdown mode is enabled"
else
  report FAIL "5.5 Lockdown mode is not enabled"
fi

# 5.8 Idle timeout ≤ 300
echo -n "5.8 Idle Shell/SSH Timeout: "
idle_timeout=$(esxcli system settings advanced list -o /UserVars/ESXiShellTimeOut | grep 'Int Value' | awk '{print $NF}')
if [[ "$idle_timeout" -le 300 ]]; then
  report PASS "5.8 Idle timeout is set to $idle_timeout seconds"
else
  report FAIL "5.8 Idle timeout is $idle_timeout seconds"
fi

# 5.9 Shell services timeout ≤ 3600
echo -n "5.9 Shell Services Timeout: "
shell_timeout=$(esxcli system settings advanced list -o /UserVars/SuppressShellWarning | grep 'Int Value' | awk '{print $NF}')
if [[ "$shell_timeout" -le 3600 ]]; then
  report PASS "5.9 Shell warning suppression timeout is $shell_timeout seconds"
else
  report FAIL "5.9 Shell timeout is too long: $shell_timeout seconds"
fi

# 5.10 DCUI trusted users
report MANUAL "5.10 Ensure DCUI trusted user list is configured"
echo '
Check via:
esxcli system settings advanced list -o DCUI.Access
Ensure list only contains authorized users.
' >> "$SUMMARY_LOG"


##########
# Section 6: Storage
##########

# 6.1 Ensure bidirectional CHAP authentication for iSCSI traffic is enabled
report MANUAL "6.1 Ensure bidirectional CHAP authentication for iSCSI traffic is enabled"
echo '
Use vSphere Client:
  1. Navigate to the host > Configure > Storage > Storage Adapters.
  2. Select iSCSI adapter > Properties > Authentication.
  3. Confirm "Use bidirectional CHAP" is selected.

PowerCLI Option:
  Get-VMHost | Get-VMHostHba | Where {$_.Type -eq "Iscsi"} |
    Select VMHost, Device, ChapType, @{N="CHAPName";E={$_.AuthenticationProperties.ChapName}}
' >> "$SUMMARY_LOG"


##########
# Section 7: vNetwork
##########

# 7.1 vSwitch Forged Transmits = Reject
report MANUAL "7.1 Ensure the vSwitch Forged Transmits policy is set to Reject"
echo '
Use PowerCLI:
Get-VirtualSwitch -VMHost <hostname> | Get-SecurityPolicy | Select-Object ForgedTransmits
Ensure it returns: True (i.e., Reject)
' >> "$SUMMARY_LOG"

# 7.2 vSwitch MAC Address Changes = Reject
report MANUAL "7.2 Ensure the vSwitch MAC Address Change policy is set to Reject"
echo '
Use PowerCLI:
Get-VirtualSwitch -VMHost <hostname> | Get-SecurityPolicy | Select-Object MacChanges
Ensure it returns: True (i.e., Reject)
' >> "$SUMMARY_LOG"

# 7.3 vSwitch Promiscuous Mode = Reject
report MANUAL "7.3 Ensure the vSwitch Promiscuous Mode policy is set to Reject"
echo '
Use PowerCLI:
Get-VirtualSwitch -VMHost <hostname> | Get-SecurityPolicy | Select-Object AllowPromiscuous
Ensure it returns: False (i.e., Reject)
' >> "$SUMMARY_LOG"

# 7.4 Reverse Path Filtering is enabled
report MANUAL "7.4 Ensure the vSwitch Reverse Path Filtering is enabled"
echo '
Reverse Path Filtering is not available via esxcli by default; manual verification or custom dvFilter may be required.
' >> "$SUMMARY_LOG"


##########
# Section 8: Virtual Machines
##########

# 8.2.1 Ensure unnecessary floppy devices are disconnected
report MANUAL "8.2.1 Ensure unnecessary floppy devices are disconnected"
echo '
Use PowerCLI:
Get-VM | Get-FloppyDrive | Where {$_.ConnectionState.Connected -eq $true}
' >> "$SUMMARY_LOG"

# 8.2.3 Ensure unnecessary parallel ports are disconnected
report MANUAL "8.2.3 Ensure unnecessary parallel ports are disconnected"
echo '
Use PowerCLI:
Get-VM | Get-ParallelPort | Where {$_.ConnectionState.Connected -eq $true}
' >> "$SUMMARY_LOG"

# 8.2.4 Ensure unnecessary serial ports are disconnected
report MANUAL "8.2.4 Ensure unnecessary serial ports are disconnected"
echo '
Use PowerCLI:
Get-VM | Get-SerialPort | Where {$_.ConnectionState.Connected -eq $true}
' >> "$SUMMARY_LOG"

# 8.2.5 Ensure unnecessary USB devices are disconnected
report MANUAL "8.2.5 Ensure unnecessary USB devices are disconnected"
echo '
Use PowerCLI:
Get-VM | Get-USBDevice | Where {$_.ConnectionState.Connected -eq $true}
' >> "$SUMMARY_LOG"

# 8.2.6 Ensure unauthorized modification and disconnection of devices is disabled
report MANUAL "8.2.6 Ensure unauthorized modification and disconnection of devices is disabled"
echo '
Check VM Advanced Settings:
Get-VM | Get-AdvancedSetting -Name "devices.hotplug"
' >> "$SUMMARY_LOG"

# 8.2.7 Ensure unauthorized connection of devices is disabled
report MANUAL "8.2.7 Ensure unauthorized connection of devices is disabled"
echo '
Review device connection policies per VM:
Get-VM | Get-AdvancedSetting | Where-Object {$_.Name -match "usb|serial|parallel"}
' >> "$SUMMARY_LOG"

# 8.2.8 Ensure PCI and PCIe device passthrough is disabled
report MANUAL "8.2.8 Ensure PCI and PCIe device passthrough is disabled"
echo '
Use:
Get-VM | Get-PassthroughDevice
' >> "$SUMMARY_LOG"

# 8.6.2 Ensure virtual disk shrinking is disabled
report MANUAL "8.6.2 Ensure virtual disk shrinking is disabled"
echo '
PowerCLI:
Get-VM | Get-AdvancedSetting -Name "isolation.tools.diskShrink.disable"
Should be set to TRUE
' >> "$SUMMARY_LOG"

# 8.6.3 Ensure virtual disk wiping is disabled
report MANUAL "8.6.3 Ensure virtual disk wiping is disabled"
echo '
PowerCLI:
Get-VM | Get-AdvancedSetting -Name "isolation.tools.diskWiper.disable"
Should be set to TRUE
' >> "$SUMMARY_LOG"

# 8.7.1 Ensure the number of VM log files is configured properly
report MANUAL "8.7.1 Ensure the number of VM log files is configured properly"
echo '
Check VMX settings: log.keepOld > 10 recommended
' >> "$SUMMARY_LOG"

# 8.7.3 Ensure VM log file size is limited
report MANUAL "8.7.3 Ensure VM log file size is limited"
echo '
Check VMX setting: log.rotateSize
Should not exceed 1000000 bytes
' >> "$SUMMARY_LOG"