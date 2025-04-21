#!/bin/bash

#!/usr/bin/env bash

# RHEL CIS Level 1 Audit Script
# Includes: 1.1.1.x (Filesystem Kernel Modules) and 1.1.2.x (Partition Config)
# Output format: [PASS], [FAIL], [MANUAL]
# Run as root

OUTPUT_FILE="cis_level1_report_rhel.txt"
> "$OUTPUT_FILE"

PASS_COUNT=0
FAIL_COUNT=0
MANUAL_COUNT=0

print_header() {
    local title="$1"
    echo -e "\n============================================================" | tee -a "$OUTPUT_FILE"
    echo -e ">> $title" | tee -a "$OUTPUT_FILE"
    echo -e "============================================================" | tee -a "$OUTPUT_FILE"
}

log_pass() { ((PASS_COUNT++)); echo -e "[PASS]   $1" | tee -a "$OUTPUT_FILE"; }
log_fail() { ((FAIL_COUNT++)); echo -e "[FAIL]   $1" | tee -a "$OUTPUT_FILE"; }
log_manual() { ((MANUAL_COUNT++)); echo -e "[MANUAL] $1" | tee -a "$OUTPUT_FILE"; }
log_note() { echo -e "         $1" | tee -a "$OUTPUT_FILE"; }

# 1.1.1.x - Kernel Module Checks
check_kernel_module_disabled() {
    local module="$1"
    
print_header "1.1.1 - Kernel Module: $module"
    local result
    result=$(modprobe -n -v "$module" 2>/dev/null)
    if echo "$result" | grep -qE 'install /bin/(true|false)'; then
        log_pass "$module is properly disabled"
        log_note "Result: $result"
    else
        log_fail "$module is NOT disabled"
        log_note "Result: $result"
    fi
}

# 1.1.2.x - Partition & Mount Option Checks
check_partition_exists() {
    local mountpoint="$1"
    
print_header "1.1.2 - Check Partition Exists: $mountpoint"
    if grep -E "^[^#].+\s+$mountpoint\s+" /etc/fstab &>/dev/null; then
        log_pass "Separate partition exists for $mountpoint"
    else
        log_fail "No separate partition found for $mountpoint in /etc/fstab"
    fi
}

check_mount_option() {
    local mountpoint="$1"
    local option="$2"
    
print_header "1.1.2 - Check $option Option on $mountpoint"
    local mnt_opts
    mnt_opts=$(mount | grep -E "on $mountpoint type" | grep -oP '\((.*?)\)' | tr -d '()')

    if echo "$mnt_opts" | grep -qw "$option"; then
        log_pass "$option option is set on $mountpoint"
    else
        log_fail "$option option is NOT set on $mountpoint"
        log_note "Current mount options: $mnt_opts"
    fi
}

echo "RHEL CIS Level 1 Audit Starting..." | tee -a "$OUTPUT_FILE"

# 1.1.1 - Kernel Modules
for module in cramfs freevxfs jffs2 hfs hfsplus squashfs udf usb-storage; do
    check_kernel_module_disabled "$module"
done

# 1.1.2 - Partition and Mount Options
for mp in /tmp /dev/shm /home /var /var/tmp /var/log /var/log/audit; do
    check_partition_exists "$mp"
done

# Mount option checks
declare -A mount_opts
mount_opts["/tmp"]="nodev nosuid noexec"
mount_opts["/dev/shm"]="nodev nosuid noexec"
mount_opts["/home"]="nodev nosuid"
mount_opts["/var"]="nodev nosuid"
mount_opts["/var/tmp"]="nodev nosuid noexec"
mount_opts["/var/log"]="nodev nosuid noexec"
mount_opts["/var/log/audit"]="nodev nosuid noexec"

for mnt in "${!mount_opts[@]}"; do
    for opt in ${mount_opts[$mnt]}; do
        check_mount_option "$mnt" "$opt"
    done
done

# Summary
print_header "Audit Summary"
echo -e "[PASS]   $PASS_COUNT" | tee -a "$OUTPUT_FILE"
echo -e "[FAIL]   $FAIL_COUNT" | tee -a "$OUTPUT_FILE"
echo -e "[MANUAL] $MANUAL_COUNT" | tee -a "$OUTPUT_FILE"
echo -e "\nAudit complete. Detailed results saved to: $OUTPUT_FILE" | tee -a "$OUTPUT_FILE"

# 1.2 - Software and Patch Management

print_header "1.2 - Software and Patch Management"

detect_package_manager() {
    if command -v dnf &>/dev/null; then
        echo "dnf"
    elif command -v yum &>/dev/null; then
        echo "yum"
    else
        echo "none"
    fi
}

PKG_MGR=$(detect_package_manager)

# 1.2.1 - Ensure GPG keys are configured (Manual)
log_manual "Ensure GPG keys are configured: Check that GPG keys exist for all repositories"

# 1.2.2 - Ensure gpgcheck is globally activated

print_header "1.2.2 - Ensure gpgcheck is globally activated"
if grep -R "^gpgcheck=1" /etc/yum.repos.d/*.repo | grep -vq '^#'; then
    log_pass "gpgcheck is enabled in repo files"
else
    log_fail "gpgcheck is not globally enabled in repos"
fi

# 1.2.3 - Ensure repo_gpgcheck is globally activated (Manual)
log_manual "Ensure repo_gpgcheck is globally activated: This may require manual validation of each repo"

# 1.2.4 - Ensure package manager repositories are configured (Manual)
log_manual "Ensure repositories are configured according to organizational policies"

# 1.2.5 - Ensure updates and patches are installed

print_header "1.2.5 - Ensure updates, patches, and security software are installed"
if [ "$PKG_MGR" != "none" ]; then
    if $PKG_MGR check-update --security &>/dev/null; then
        log_pass "No outstanding security updates"
    else
        log_fail "Security updates are available"
    fi
else
    log_fail "Could not determine package manager"
fi

# 1.3 - Configure Secure Boot Settings

print_header "1.3 - Configure Secure Boot Settings"

# 1.3.1 - Ensure bootloader password is set

print_header "1.3.1 - Ensure bootloader password is set"
if grep -Eq "^GRUB2_PASSWORD=" /etc/grub.d/00_header; then
    log_pass "GRUB2 password is set"
else
    log_fail "GRUB2 password is NOT set"
fi

# 1.3.2 - Ensure permissions on bootloader config are configured

print_header "1.3.2 - Ensure permissions on bootloader config are configured"
boot_config="/boot/grub2/grub.cfg"
if [ -e "$boot_config" ]; then
    perms=$(stat -c "%a" "$boot_config")
    owner=$(stat -c "%U:%G" "$boot_config")
    if [ "$perms" == "400" ] && [ "$owner" == "root:root" ]; then
        log_pass "Permissions and ownership on $boot_config are secure (400 root:root)"
    else
        log_fail "Incorrect permissions or ownership on $boot_config (Found: $perms $owner)"
    fi
else
    log_fail "$boot_config not found"
fi

# 1.4 - Configure Additional Process Hardening

print_header "1.4 - Additional Process Hardening"

# 1.4.1 - Ensure address space layout randomization (ASLR) is enabled

print_header "1.4.1 - Ensure ASLR is enabled"
aslr_value=$(sysctl -n kernel.randomize_va_space)
if [ "$aslr_value" -eq 2 ]; then
    log_pass "ASLR is enabled (kernel.randomize_va_space = 2)"
else
    log_fail "ASLR is NOT properly enabled (Found: $aslr_value)"
fi

# 1.4.2 - Ensure ptrace_scope is restricted

print_header "1.4.2 - Ensure ptrace_scope is restricted"
ptrace_val=$(sysctl -n kernel.yama.ptrace_scope 2>/dev/null)
if [ "$ptrace_val" -ge 1 ]; then
    log_pass "ptrace_scope is restricted (>=1)"
else
    log_fail "ptrace_scope is NOT restricted (Found: $ptrace_val)"
fi

# 1.4.3 - Ensure core dump backtraces are disabled

print_header "1.4.3 - Ensure core dump backtraces are disabled"
backtrace_val=$(sysctl -n kernel.core_pattern 2>/dev/null)
if echo "$backtrace_val" | grep -q "core"; then
    log_fail "Core dump backtrace pattern found: $backtrace_val"
else
    log_pass "Core dump backtrace is disabled"
fi

# 1.4.4 - Ensure core dump storage is disabled

print_header "1.4.4 - Ensure core dump storage is disabled"
core_dump_setting=$(grep -E '^\*\s+hard\s+core\s+0' /etc/security/limits.conf /etc/security/limits.d/*.conf 2>/dev/null)
if [ -n "$core_dump_setting" ]; then
    log_pass "Core dump storage is disabled in limits.conf"
else
    log_fail "Core dump storage is NOT disabled in limits.conf"
fi

# 1.5 - Mandatory Access Control (SELinux)

print_header "1.5 - Mandatory Access Control (SELinux)"

# 1.5.1.1 - Ensure SELinux is installed

print_header "1.5.1.1 - Ensure SELinux is installed"
if rpm -q libselinux &>/dev/null; then
    log_pass "SELinux is installed (libselinux)"
else
    log_fail "SELinux is NOT installed"
fi

# 1.5.1.2 - Ensure SELinux is not disabled in bootloader

print_header "1.5.1.2 - Ensure SELinux is not disabled in bootloader config"
if grep -E '(^GRUB_CMDLINE_LINUX=.*selinux=0|enforcing=0)' /etc/default/grub &>/dev/null; then
    log_fail "SELinux is disabled in GRUB config"
else
    log_pass "SELinux is NOT disabled in GRUB config"
fi

# 1.5.1.3 - Ensure SELinux policy is configured

print_header "1.5.1.3 - Ensure SELinux policy is configured"
selinux_config_file="/etc/selinux/config"
if [ -f "$selinux_config_file" ]; then
    policy=$(grep "^SELINUXTYPE=" "$selinux_config_file" | cut -d= -f2)
    if [ "$policy" == "targeted" ] || [ "$policy" == "mls" ]; then
        log_pass "SELinux policy is configured as: $policy"
    else
        log_fail "SELinux policy is not set properly (Found: $policy)"
    fi
else
    log_fail "SELinux config file not found"
fi

# 1.5.1.4 - Ensure SELinux mode is not disabled

print_header "1.5.1.4 - Ensure SELinux mode is not disabled"
mode=$(grep "^SELINUX=" "$selinux_config_file" | cut -d= -f2)
if [ "$mode" != "disabled" ]; then
    log_pass "SELinux mode is not disabled ($mode)"
else
    log_fail "SELinux is disabled"
fi

# 1.5.1.5 - Ensure SELinux mode is enforcing

print_header "1.5.1.6 - Ensure no unconfined services exist"
if ps -eZ | grep unconfined_service_t &>/dev/null; then
    log_fail "Unconfined services are running"
else
    log_pass "No unconfined services found"
fi

# 1.5.1.7 - Ensure mcstrans is not installed

print_header "1.5.1.7 - Ensure mcstrans is not installed"
if rpm -q mcstrans &>/dev/null; then
    log_fail "mcstrans is installed"
else
    log_pass "mcstrans is NOT installed"
fi

# 1.5.1.8 - Ensure SETroubleshoot is not installed

print_header "1.5.1.8 - Ensure SETroubleshoot is not installed"
if rpm -q setroubleshoot &>/dev/null; then
    log_fail "SETroubleshoot is installed"
else
    log_pass "SETroubleshoot is NOT installed"
fi

# 1.6 - Configure System-Wide Crypto Policy

print_header "1.6 - Configure System-Wide Crypto Policy"

# 1.6.1 - Ensure crypto policy is not set to legacy

print_header "1.6.1 - Ensure crypto policy is not set to legacy"
crypto_policy=$(update-crypto-policies --show 2>/dev/null)
if [ "$crypto_policy" == "LEGACY" ]; then
    log_fail "Crypto policy is set to LEGACY"
else
    log_pass "Crypto policy is not LEGACY (Found: $crypto_policy)"
fi

# 1.6.2 - Ensure system-wide crypto policy disables sha1

print_header "1.6.2 - Ensure crypto policy disables SHA1 support"
if grep -q -i "sha1" /etc/crypto-policies/back-ends/* 2>/dev/null; then
    log_fail "SHA1 support is enabled in crypto policy"
else
    log_pass "SHA1 support is NOT found in crypto policy backend files"
fi

# 1.6.3 - Ensure system-wide crypto policy disables CBC for SSH

print_header "1.6.3 - Ensure crypto policy disables CBC for SSH"
if grep -q -i "cbc" /etc/crypto-policies/back-ends/openssh.config 2>/dev/null; then
    log_fail "CBC mode ciphers found in SSH crypto policy"
else
    log_pass "No CBC mode ciphers found in SSH crypto policy"
fi

# 1.6.4 - Ensure system-wide crypto policy disables MACs < 128 bits

print_header "1.6.4 - Ensure crypto policy disables MACs less than 128 bits"
if grep -iE 'hmac-md5|hmac-sha1' /etc/crypto-policies/back-ends/openssh.config 2>/dev/null; then
    log_fail "Weak HMAC algorithms found (MD5/SHA1)"
else
    log_pass "No weak HMAC algorithms found (MD5/SHA1)"
fi

# 1.7 - Configure Command Line Warning Banners

print_header "1.7 - Configure Command Line Warning Banners"

# Expected banner text pattern
expected_banner="(\*\*\*|\bWARNING\b|UNAUTHORIZED)"

check_banner_content() {
    local file="$1"
    print_header "Check Banner Content: $file"
    if [ -f "$file" ]; then
        if grep -Eiq "$expected_banner" "$file"; then
            log_pass "$file contains a warning banner"
        else
            log_fail "$file does NOT contain an appropriate warning"
        fi
    else
        log_fail "$file does not exist"
    fi
}

check_permissions "/etc/motd" "644"
check_permissions "/etc/issue" "644"
check_permissions "/etc/issue.net" "644"

check_banner_content "/etc/motd"
check_banner_content "/etc/issue"
check_banner_content "/etc/issue.net"

# 1.8 - Configure GNOME Display Manager (GDM)

print_header "1.8 - Configure GNOME Display Manager (GDM)"

# 1.8.1 - Ensure GDM is removed

print_header "1.8.1 - Ensure GDM is removed"
if rpm -q gdm &>/dev/null; then
    log_fail "GDM is installed"
else
    log_pass "GDM is NOT installed"
fi

# 1.8.2 - Ensure GDM login banner is configured

print_header "1.8.2 - Ensure GDM login banner is configured"
gdm_banner_file="/etc/dconf/db/gdm.d/01-banner-message"
if [ -f "$gdm_banner_file" ] && grep -q "banner-message-enable=true" "$gdm_banner_file"; then
    log_pass "GDM login banner is configured"
else
    log_fail "GDM login banner is NOT configured"
fi

# 1.8.3 - Ensure disable-user-list option is enabled

print_header "1.8.3 - Ensure GDM disable-user-list option is enabled"
if [ -f "$gdm_banner_file" ] && grep -q "disable-user-list=true" "$gdm_banner_file"; then
    log_pass "GDM disable-user-list is enabled"
else
    log_fail "GDM disable-user-list is NOT enabled"
fi

# 1.8.4 - Ensure screen locks when the user is idle

print_header "1.8.4 - Ensure GDM screen lock when idle"
lock_idle_file="/etc/dconf/db/gdm.d/00-screensaver"
if [ -f "$lock_idle_file" ] && grep -q "idle-delay=uint32 5" "$lock_idle_file"; then
    log_pass "GDM screen lock idle delay is configured"
else
    log_fail "GDM screen lock idle delay is not properly configured"
fi

# 1.8.5 - Ensure screen lock cannot be overridden

print_header "1.8.5 - Ensure GDM screen lock cannot be overridden"
if [ -f "$lock_idle_file" ] && grep -q "lock-enabled=true" "$lock_idle_file"; then
    log_pass "GDM lock-enabled is set"
else
    log_fail "GDM lock-enabled is not set"
fi

# 1.8.6 - Ensure auto-mounting of removable media is disabled

print_header "1.8.6 - Ensure automatic mounting is disabled"
auto_mount_file="/etc/dconf/db/gdm.d/00-media"
if [ -f "$auto_mount_file" ] && grep -q "automount=false" "$auto_mount_file"; then
    log_pass "Automatic mounting is disabled"
else
    log_fail "Automatic mounting is NOT disabled"
fi

# 1.8.7 - Ensure automount override is not set

print_header "1.8.7 - Ensure automount override is not configured"
if [ -f "$auto_mount_file" ] && grep -q "automount-open=false" "$auto_mount_file"; then
    log_pass "Automount override is disabled"
else
    log_fail "Automount override is NOT disabled"
fi

# 1.8.8 - Ensure autorun-never is enabled

print_header "1.8.8 - Ensure autorun-never is enabled"
if [ -f "$auto_mount_file" ] && grep -q "autorun-never=true" "$auto_mount_file"; then
    log_pass "autorun-never is enabled"
else
    log_fail "autorun-never is NOT enabled"
fi

# 1.8.9 - Ensure autorun-never is not overridden

print_header "1.8.9 - Ensure autorun-never is not overridden"
if ! grep -r "autorun-never=false" /etc/dconf/db/gdm.d/ &>/dev/null; then
    log_pass "No override found for autorun-never"
else
    log_fail "Found override disabling autorun-never"
fi

# 1.8.10 - Ensure XDMCP is not enabled

print_header "1.8.10 - Ensure XDMCP is not enabled"
if grep -q "Enable=true" /etc/gdm/custom.conf 2>/dev/null; then
    log_fail "XDMCP is enabled in GDM custom.conf"
else
    log_pass "XDMCP is NOT enabled"
fi

# 2.1 - Configure Time Synchronization

print_header "2.1 - Time Synchronization"

# 2.1.1 - Ensure time sync is in use (chrony or ntpd)

print_header "2.1.1 - Ensure time synchronization service is in use"
if systemctl is-enabled chronyd &>/dev/null || systemctl is-enabled ntpd &>/dev/null; then
    log_pass "Time synchronization service is enabled"
else
    log_fail "No time synchronization service is enabled (chronyd or ntpd)"
fi

# 2.1.2 - Ensure chrony is configured

print_header "2.1.2 - Ensure chrony is configured"
if [ -f /etc/chrony.conf ]; then
    if grep -Eq "^server|^pool" /etc/chrony.conf; then
        log_pass "chrony is configured with server or pool"
    else
        log_fail "chrony.conf does not contain server or pool entries"
    fi
else
    log_manual "chrony is not configured or file is missing"
fi

# 2.1.3 - Ensure chrony is not run as root (applies to newer systems)

print_header "2.1.3 - Ensure chrony is not run as root"
chrony_user=$(ps -eo user,comm | grep chronyd | awk '{print $1}' | head -1)
if [ "$chrony_user" != "root" ] && [ -n "$chrony_user" ]; then
    log_pass "chrony is running as $chrony_user"
else
    log_fail "chrony is running as root or not running"
fi

# 2.2 - Special Purpose Services

print_header "2.2 - Special Purpose Services"

declare -a special_services=(
    autofs avahi-daemon dhcpd named dnsmasq samba vsftpd dovecot nfs-server ypserv cups     rpcbind rsyncd snmpd telnetd tftpd squid httpd xinetd
)

for svc in "${special_services[@]}"; do
    
print_header "2.2 - Check service: $svc"
    if rpm -q "$svc" &>/dev/null; then
        if systemctl is-enabled "$svc" &>/dev/null; then
            log_fail "$svc is installed and enabled"
        else
            log_pass "$svc is installed but disabled"
        fi
    else
        log_pass "$svc is not installed"
    fi
done

# 2.2.21 - Ensure MTA configured for local-only

print_header "2.2.21 - Ensure MTA is configured for local-only"
if grep -E "^inet_interfaces\s*=\s*loopback-only" /etc/postfix/main.cf &>/dev/null; then
    log_pass "Postfix MTA is configured for local-only"
else
    log_fail "Postfix MTA is not restricted to loopback-only"
fi

# 2.2.22 - Manual check for only approved services listening

print_header "2.2.22 - Only approved services listening (Manual)"
log_manual "Review open ports and compare to approved service list: use 'ss -tulnp'"

# 2.3 - Configure Service Clients

print_header "2.3 - Service Clients"

declare -a banned_clients=(
    ftp ldap ypbind telnet tftp
)

for client in "${banned_clients[@]}"; do
    
print_header "2.3 - Check client package: $client"
    if rpm -q "$client" &>/dev/null; then
        log_fail "$client client is installed"
    else
        log_pass "$client client is NOT installed"
    fi
done

# 3.1 - Configure Network Devices

print_header "3.1 - Configure Network Devices"

# 3.1.1 - Ensure IPv6 status is identified (Manual)

print_header "3.1.1 - Ensure IPv6 status is identified"
log_manual "Manually confirm IPv6 configuration status with: sysctl net.ipv6.conf.all.disable_ipv6"

# 3.1.2 - Ensure wireless interfaces are disabled

print_header "3.1.2 - Ensure wireless interfaces are disabled"
wireless_ifaces=$(iw dev 2>/dev/null | grep Interface | awk '{print $2}')
if [ -z "$wireless_ifaces" ]; then
    log_pass "No wireless interfaces detected"
else
    log_fail "Wireless interfaces detected: $wireless_ifaces"
fi

# 3.1.3 - Ensure Bluetooth services are not in use

print_header "3.1.3 - Ensure Bluetooth services are not in use"
if rpm -q bluez &>/dev/null; then
    if systemctl is-enabled bluetooth &>/dev/null; then
        log_fail "Bluetooth service is installed and enabled"
    else
        log_pass "Bluetooth is installed but disabled"
    fi
else
    log_pass "Bluetooth is not installed"
fi

# 3.2 - Configure Network Kernel Modules

print_header "3.2 - Configure Network Kernel Modules"

# 3.2.x - Ensure certain network-related modules are not available
for module in dccp tipc rds sctp; do
    
print_header "3.2 - Check module: $module"
    result=$(modprobe -n -v "$module" 2>/dev/null)
    if echo "$result" | grep -qE 'install /bin/(true|false)'; then
        log_pass "$module is properly disabled"
        log_note "Result: $result"
    else
        log_fail "$module is NOT disabled"
        log_note "Result: $result"
    fi
done

# 3.3 - Configure Network Kernel Parameters

print_header "3.3 - Network Kernel Parameters"

check_sysctl_value() {
    local key="$1"
    local expected="$2"
    print_header "Check sysctl: $key"
    val=$(sysctl -n "$key" 2>/dev/null)
    if [ "$val" == "$expected" ]; then
        log_pass "$key is set to $expected"
    else
        log_fail "$key is $val (Expected: $expected)"
    fi
}

# 3.3.1 - Ensure ip forwarding is disabled
check_sysctl_value "net.ipv4.ip_forward" "0"
check_sysctl_value "net.ipv6.conf.all.forwarding" "0"

# 3.3.2 - Ensure packet redirect sending is disabled
check_sysctl_value "net.ipv4.conf.all.send_redirects" "0"
check_sysctl_value "net.ipv4.conf.default.send_redirects" "0"

# 3.3.3 - Ensure bogus icmp responses are ignored
check_sysctl_value "net.ipv4.icmp_ignore_bogus_error_responses" "1"

# 3.3.4 - Ensure broadcast icmp requests are ignored
check_sysctl_value "net.ipv4.icmp_echo_ignore_broadcasts" "1"

# 3.3.5 - Ensure icmp redirects are not accepted
check_sysctl_value "net.ipv4.conf.all.accept_redirects" "0"
check_sysctl_value "net.ipv4.conf.default.accept_redirects" "0"

# 3.3.6 - Ensure secure icmp redirects are not accepted
check_sysctl_value "net.ipv4.conf.all.secure_redirects" "0"
check_sysctl_value "net.ipv4.conf.default.secure_redirects" "0"

# 3.3.7 - Ensure reverse path filtering is enabled
check_sysctl_value "net.ipv4.conf.all.rp_filter" "1"
check_sysctl_value "net.ipv4.conf.default.rp_filter" "1"

# 3.3.8 - Ensure source routed packets are not accepted
check_sysctl_value "net.ipv4.conf.all.accept_source_route" "0"
check_sysctl_value "net.ipv4.conf.default.accept_source_route" "0"
check_sysctl_value "net.ipv6.conf.all.accept_source_route" "0"
check_sysctl_value "net.ipv6.conf.default.accept_source_route" "0"

# 3.3.9 - Ensure suspicious packets are logged
check_sysctl_value "net.ipv4.conf.all.log_martians" "1"
check_sysctl_value "net.ipv4.conf.default.log_martians" "1"

# 3.3.10 - Ensure TCP SYN cookies are enabled
check_sysctl_value "net.ipv4.tcp_syncookies" "1"

# 3.3.11 - Ensure IPv6 router advertisements are not accepted
check_sysctl_value "net.ipv6.conf.all.accept_ra" "0"
check_sysctl_value "net.ipv6.conf.default.accept_ra" "0"

# 3.4 - Configure Host-Based Firewall

print_header "3.4 - Host-Based Firewall"

# 3.4.1.1 - Ensure nftables is installed

print_header "3.4.1.1 - Ensure nftables is installed"
if rpm -q nftables &>/dev/null; then
    log_pass "nftables is installed"
else
    log_fail "nftables is NOT installed"
fi

# 3.4.1.2 - Ensure only one firewall utility is in use

print_header "3.4.1.2 - Ensure only one firewall utility is active"
services_enabled=$(systemctl list-unit-files | grep enabled | grep -E "nftables|iptables|firewalld" | awk '{print $1}')
count=$(echo "$services_enabled" | wc -l)
if [ "$count" -eq 1 ]; then
    log_pass "Only one firewall service is enabled: $services_enabled"
else
    log_fail "Multiple or no firewall services are enabled: $services_enabled"
fi

# 3.4.2.1 - Ensure nftables base chains exist

print_header "3.4.2.1 - Ensure nftables base chains exist"
if nft list ruleset | grep -q "hook input"; then
    log_pass "nftables base chains are defined"
else
    log_fail "nftables base chains are NOT found"
fi

# 3.4.2.2 - Ensure loopback traffic is configured

print_header "3.4.2.2 - Ensure loopback traffic is configured in nftables"
if nft list ruleset | grep -q "iif lo accept"; then
    log_pass "Loopback interface rules exist in nftables"
else
    log_fail "Loopback interface rules are missing from nftables"
fi

# 3.4.2.3 - Ensure firewalld drops unnecessary services and ports (Manual)

print_header "3.4.2.3 - Review firewalld for unnecessary services/ports"
log_manual "Review firewalld config: 'firewall-cmd --list-all' and compare against approved baseline"

# 3.4.2.4 - Ensure nftables established connections are accepted (Manual)

print_header "3.4.2.4 - Ensure established connections are allowed"
log_manual "Check for 'ct state established,related accept' in nftables input chain"

# 3.4.2.5 - Ensure default deny policy in nftables

print_header "3.4.2.5 - Ensure default deny policy in nftables"
if nft list ruleset | grep -q "policy drop"; then
    log_pass "Default deny (drop) policy is configured"
else
    log_fail "Default deny (drop) policy is NOT found"
fi

# 4.1 - Configure Job Schedulers

print_header "4.1 - Configure Job Schedulers"

# 4.1.1 - Configure cron

print_header "4.1.1 - Cron Configuration Checks"

# 4.1.1.1 - Ensure cron daemon is enabled and active
if systemctl is-enabled crond &>/dev/null && systemctl is-active crond &>/dev/null; then
    log_pass "cron daemon is enabled and active"
else
    log_fail "cron daemon is not properly enabled/active"
fi

# 4.1.1.2 to 4.1.1.7 - Check permissions on cron system files/directories
declare -A cron_paths=(
    ["/etc/crontab"]="600"
    ["/etc/cron.hourly"]="700"
    ["/etc/cron.daily"]="700"
    ["/etc/cron.weekly"]="700"
    ["/etc/cron.monthly"]="700"
    ["/etc/cron.d"]="700"
)

for path in "${!cron_paths[@]}"; do
    check_permissions "$path" "${cron_paths[$path]}"
done

# 4.1.1.8 - Ensure crontab is restricted to authorized users

print_header "4.1.1.8 - Ensure crontab is restricted"
if [ -f /etc/cron.allow ]; then
    log_pass "/etc/cron.allow is present (crontab restricted)"
else
    log_fail "/etc/cron.allow is missing (crontab not restricted)"
fi

# 4.1.2 - Configure 'at'

print_header "4.1.2 - Configure at command"

# 4.1.2.1 - Ensure at is restricted to authorized users
if [ -f /etc/at.allow ]; then
    log_pass "/etc/at.allow is present (at restricted)"
else
    log_fail "/etc/at.allow is missing (at not restricted)"
fi

# 4.2 - Configure SSH Server

print_header "4.2 - SSH Server Configuration"

sshd_config="/etc/ssh/sshd_config"

check_sshd_setting() {
    local key="$1"
    local expected="$2"
    print_header "Check sshd_config: $key"
    if grep -Eiq "^\s*$key\s+$expected" "$sshd_config"; then
        log_pass "$key is set to $expected"
    else
        log_fail "$key is not set to $expected"
    fi
}

# 4.2.1 - Permissions on sshd_config
check_permissions "$sshd_config" "600"

# 4.2.2 - Private key permissions

print_header "4.2.2 - SSH private host key file permissions"
for key in /etc/ssh/*_key; do
    [ -f "$key" ] && check_permissions "$key" "600"
done

# 4.2.3 - Public key permissions

print_header "4.2.3 - SSH public host key file permissions"
for key in /etc/ssh/*.pub; do
    [ -f "$key" ] && check_permissions "$key" "644"
done

# 4.2.4 to 4.2.22 - sshd_config settings
check_sshd_setting "PermitRootLogin" "no"
check_sshd_setting "PermitEmptyPasswords" "no"
check_sshd_setting "Protocol" "2"
check_sshd_setting "X11Forwarding" "no"
check_sshd_setting "AllowTcpForwarding" "no"
check_sshd_setting "MaxAuthTries" "4"
check_sshd_setting "ClientAliveInterval" "300"
check_sshd_setting "ClientAliveCountMax" "0"
check_sshd_setting "LoginGraceTime" "60"
check_sshd_setting "UsePAM" "yes"
check_sshd_setting "IgnoreRhosts" "yes"
check_sshd_setting "HostbasedAuthentication" "no"
check_sshd_setting "PermitUserEnvironment" "no"
check_sshd_setting "MaxSessions" "10"
check_sshd_setting "MaxStartups" "10:30:60"
check_sshd_setting "Banner" "/etc/issue.net"

# 4.3 - Configure Privilege Escalation

print_header "4.3 - Privilege Escalation Controls"

# 4.3.1 - Ensure sudo is installed

print_header "4.3.1 - Ensure sudo is installed"
if rpm -q sudo &>/dev/null; then
    log_pass "sudo is installed"
else
    log_fail "sudo is NOT installed"
fi

# 4.3.2 - Ensure sudo commands use pty

print_header "4.3.2 - Ensure sudo commands use pty"
if grep -q "^Defaults.*use_pty" /etc/sudoers /etc/sudoers.d/* 2>/dev/null; then
    log_pass "sudo is configured to use pty"
else
    log_fail "sudo is NOT configured to use pty"
fi

# 4.3.3 - Ensure sudo log file exists

print_header "4.3.3 - Ensure sudo log file is configured"
if grep -q "^Defaults.*logfile=" /etc/sudoers /etc/sudoers.d/* 2>/dev/null; then
    log_pass "sudo is configured to log commands"
else
    log_fail "sudo log file configuration is missing"
fi

# 4.3.4 - Ensure password is required for sudo

print_header "4.3.4 - Ensure password is required for sudo"
if grep -Eqr '^\s*[^#].*ALL\s*=\s*\(ALL(:ALL)?\)\s*ALL' /etc/sudoers /etc/sudoers.d/; then
    log_pass "sudo requires password for commands"
else
    log_fail "sudo may allow passwordless access"
fi

# 4.3.5 - Ensure re-authentication is not globally disabled

print_header "4.3.5 - Ensure sudo re-authentication is not globally disabled"
if grep -Eq "^Defaults\s+!authenticate" /etc/sudoers /etc/sudoers.d/* 2>/dev/null; then
    log_fail "sudo has '!authenticate' set"
else
    log_pass "sudo re-authentication is not globally disabled"
fi

# 4.3.6 - Ensure sudo authentication timeout is configured

print_header "4.3.6 - Ensure sudo authentication timeout is configured"
if grep -Eq "^Defaults\s+timestamp_timeout=" /etc/sudoers /etc/sudoers.d/* 2>/dev/null; then
    log_pass "sudo authentication timeout is configured"
else
    log_fail "sudo authentication timeout is not explicitly configured"
fi

# 4.3.7 - Ensure access to su is restricted

print_header "4.3.7 - Ensure access to 'su' is restricted"
if grep -q "^auth\s\+required\s\+pam_wheel.so" /etc/pam.d/su; then
    log_pass "Access to 'su' is restricted to members of the wheel group"
else
    log_fail "Access to 'su' is NOT restricted"
fi

# 4.4 - Configure Pluggable Authentication Modules (PAM)

print_header "4.4 - PAM Configuration"

# 4.4.1.1 - Ensure pam is installed

print_header "4.4.1.1 - Ensure pam is installed"
if rpm -q pam &>/dev/null; then
    log_pass "pam is installed"
else
    log_fail "pam is NOT installed"
fi

# 4.4.1.2 - Ensure authselect is installed

print_header "4.4.1.2 - Ensure authselect is installed"
if rpm -q authselect &>/dev/null; then
    log_pass "authselect is installed"
else
    log_fail "authselect is NOT installed"
fi

# 4.4.2.1 - Ensure active authselect profile includes pam modules

print_header "4.4.2.1 - Ensure active authselect profile uses pam modules"
if authselect current | grep -q "with-faillock"; then
    log_pass "authselect profile includes pam modules (e.g. faillock)"
else
    log_fail "authselect profile may not include required pam modules"
fi

# 4.4.2.2 - Ensure pam_faillock is enabled

print_header "4.4.2.2 - Ensure pam_faillock module is enabled"
if grep -r "pam_faillock.so" /etc/pam.d/ &>/dev/null; then
    log_pass "pam_faillock is enabled"
else
    log_fail "pam_faillock is NOT found in PAM config"
fi

# 4.4.2.3 - Ensure pam_pwquality is enabled

print_header "4.4.2.3 - Ensure pam_pwquality module is enabled"
if grep -r "pam_pwquality.so" /etc/pam.d/ &>/dev/null; then
    log_pass "pam_pwquality is enabled"
else
    log_fail "pam_pwquality is NOT found in PAM config"
fi

# 4.4.2.4 - Ensure pam_pwhistory is enabled

print_header "4.4.2.4 - Ensure pam_pwhistory module is enabled"
if grep -r "pam_pwhistory.so" /etc/pam.d/ &>/dev/null; then
    log_pass "pam_pwhistory is enabled"
else
    log_fail "pam_pwhistory is NOT found in PAM config"
fi

# 4.4.2.5 - Ensure pam_unix is enabled

print_header "4.4.2.5 - Ensure pam_unix module is enabled"
if grep -r "pam_unix.so" /etc/pam.d/ &>/dev/null; then
    log_pass "pam_unix is enabled"
else
    log_fail "pam_unix is NOT found in PAM config"
fi

# 4.5 - User Accounts and Environment

print_header "4.5 - User Accounts and Environment"

# 4.5.1.1 - Ensure strong password hashing algorithm is configured

print_header "4.5.1.1 - Ensure strong password hashing algorithm is configured"
if grep -Eq "^\s*ENCRYPT_METHOD\s+SHA512" /etc/login.defs; then
    log_pass "Password hashing algorithm is SHA512"
else
    log_fail "Password hashing algorithm is not SHA512"
fi

# 4.5.1.2 - Ensure password expiration is 365 days or less

print_header "4.5.1.2 - Ensure PASS_MAX_DAYS <= 365"
if grep -Eq "^\s*PASS_MAX_DAYS\s+[1-9][0-9]?[0-9]?$" /etc/login.defs; then
    log_pass "PASS_MAX_DAYS is 365 or less"
else
    log_fail "PASS_MAX_DAYS exceeds 365 or is not set"
fi

# 4.5.1.3 - Ensure password expiration warning >= 7 days

print_header "4.5.1.3 - Ensure PASS_WARN_AGE >= 7"
if grep -Eq "^\s*PASS_WARN_AGE\s+[7-9]|[1-9][0-9]+" /etc/login.defs; then
    log_pass "PASS_WARN_AGE is 7 or more"
else
    log_fail "PASS_WARN_AGE is below 7 or not set"
fi

# 4.5.1.4 - Ensure inactive password lock is 30 days or less

print_header "4.5.1.4 - Ensure inactive password lock is 30 days or less"
inactive_days=$(useradd -D | grep INACTIVE | cut -d= -f2)
if [ "$inactive_days" -le 30 ] 2>/dev/null; then
    log_pass "Default INACTIVE password lock is set to $inactive_days days"
else
    log_fail "INACTIVE password lock exceeds 30 days or is unset"
fi

# 4.5.1.5 - Ensure all users have changed their password

print_header "4.5.1.5 - Ensure all users have last password change date in the past"
invalid_lastchg=$(awk -F: '($2!="*LK*" && $2!="!" && $2!="*NP*" && $3 < 1000 && $7!="/sbin/nologin" && $7!="/bin/false") {print $1}' /etc/shadow)
if [ -z "$invalid_lastchg" ]; then
    log_pass "All users have a valid last password change date"
else
    log_fail "Some users may not have valid password change dates: $invalid_lastchg"
fi

# 4.5.2.1 - Ensure default group for root is GID 0

print_header "4.5.2.1 - Ensure root's default group is GID 0"
if [ "$(grep ^root: /etc/passwd | cut -d: -f4)" -eq 0 ]; then
    log_pass "Root group is correctly set to GID 0"
else
    log_fail "Root group is NOT GID 0"
fi

# 4.5.2.2 - Ensure root umask is configured

print_header "4.5.2.2 - Ensure root umask is configured in /etc/profile"
if grep -Eq "umask\s+(027|077)" /etc/profile; then
    log_pass "Root umask is configured in /etc/profile"
else
    log_fail "Root umask is not configured properly in /etc/profile"
fi

# 4.5.2.3 - Ensure system accounts are secured

print_header "4.5.2.3 - Ensure system accounts are non-login"
bad_sys_users=$(awk -F: '($3<1000 && $1!="root" && $7!="/usr/sbin/nologin" && $7!="/sbin/nologin") {print $1}' /etc/passwd)
if [ -z "$bad_sys_users" ]; then
    log_pass "All system accounts use nologin shell"
else
    log_fail "Some system accounts have interactive shells: $bad_sys_users"
fi

# 4.5.2.4 - Ensure root password is set

print_header "4.5.2.4 - Ensure root password is set"
if sudo grep -q "^root:[!*]" /etc/shadow; then
    log_fail "Root account appears locked or passwordless"
else
    log_pass "Root account has a password set"
fi

# 4.5.3.1 - Ensure nologin is not listed in /etc/shells

print_header "4.5.3.1 - Ensure /etc/shells does not list nologin"
if grep -Eq "/sbin/nologin" /etc/shells; then
    log_fail "/etc/shells contains nologin"
else
    log_pass "/etc/shells does NOT list nologin"
fi

# 4.5.3.2 - Ensure default user shell timeout is configured

print_header "4.5.3.2 - Ensure default TMOUT is set"
if grep -Eq "TMOUT=900" /etc/profile /etc/bashrc; then
    log_pass "Default user shell timeout (TMOUT) is set"
else
    log_fail "TMOUT is not set or not set to 900"
fi

# 4.5.3.3 - Ensure default user umask is configured

print_header "4.5.3.3 - Ensure default user umask is configured"
if grep -Eq "umask\s+(027|077)" /etc/profile /etc/bashrc; then
    log_pass "Default user umask is set to 027 or 077"
else
    log_fail "Default user umask is not configured correctly"
fi

# 5.1 - Configure Logging

print_header "5.1 - Configure Logging"

# 5.1.1.1 - Ensure rsyslog is installed

print_header "5.1.1.1 - Ensure rsyslog is installed"
if rpm -q rsyslog &>/dev/null; then
    log_pass "rsyslog is installed"
else
    log_fail "rsyslog is NOT installed"
fi

# 5.1.1.2 - Ensure rsyslog service is enabled (manual if using journald)

print_header "5.1.1.2 - Ensure rsyslog service is enabled"
if systemctl is-enabled rsyslog &>/dev/null; then
    log_pass "rsyslog is enabled"
else
    log_manual "rsyslog is not enabled (may use journald exclusively)"
fi

# 5.1.1.4 - Ensure rsyslog default file permissions are configured

print_header "5.1.1.4 - Ensure rsyslog default file permissions are configured"
if grep -Eq "^\$FileCreateMode\s+0640" /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null; then
    log_pass "rsyslog default file permissions are set to 0640"
else
    log_fail "rsyslog file permissions not properly set (missing \$FileCreateMode 0640)"
fi

# 5.1.1.7 - Ensure rsyslog is not configured to receive logs from remote clients

print_header "5.1.1.7 - Ensure rsyslog is not configured to receive logs from remote clients"
if grep -Eq "^(\s*module\(load|input\(type=imudp|imtcp)" /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null; then
    log_fail "rsyslog is configured to receive logs (UDP/TCP input modules)"
else
    log_pass "rsyslog is NOT configured to receive logs from remote clients"
fi

# Manual checks for remote logging and journald forwarding

print_header "5.1.1.6 - Ensure rsyslog forwards logs remotely"
log_manual "Check if rsyslog forwards to remote host via *.@@hostname in rsyslog config"


print_header "5.1.2 - Configure journald"
log_manual "Check journald settings manually: /etc/systemd/journald.conf for Storage, ForwardToSyslog"

# 5.1.3 - Ensure logrotate is configured

print_header "5.1.3 - Ensure logrotate is configured"
if [ -f /etc/logrotate.conf ]; then
    log_pass "logrotate is present"
else
    log_fail "logrotate configuration file not found"
fi

# 5.2 - Configure System Accounting (auditd)

print_header "5.2 - System Accounting (auditd)"

# 5.2.1.1 - Ensure audit is installed

print_header "5.2.1.1 - Ensure audit is installed"
if rpm -q audit &>/dev/null; then
    log_pass "audit package is installed"
else
    log_fail "audit package is NOT installed"
fi

# 5.2.1.2 - Ensure auditing for processes that start prior to auditd is enabled

print_header "5.2.1.4 - Ensure auditd service is enabled"
if systemctl is-enabled auditd &>/dev/null; then
    log_pass "auditd service is enabled"
else
    log_fail "auditd service is NOT enabled"
fi

# 5.2.2.2 - Ensure audit logs are not automatically deleted

print_header "5.2.2.3 - Ensure system shuts down when audit logs are full"
if grep -q "^admin_space_left_action\s*=\s*halt" /etc/audit/auditd.conf; then
    log_pass "System is configured to halt when audit logs are full"
else
    log_fail "System is NOT set to halt when audit logs are full"
fi

# 5.2.3.20 - Ensure audit configuration is immutable

print_header "5.3 - File Integrity Checking (AIDE)"

# 5.3.1 - Ensure AIDE is installed

print_header "5.3.1 - Ensure AIDE is installed"
if rpm -q aide &>/dev/null; then
    log_pass "AIDE is installed"
else
    log_fail "AIDE is NOT installed"
fi

# 5.3.2 - Ensure filesystem integrity is regularly checked

print_header "5.3.2 - Ensure filesystem integrity is regularly checked"
if [ -f /etc/cron.daily/aide ] || grep -qr aide /etc/cron* /etc/anacrontab; then
    log_pass "AIDE is scheduled via cron or anacron"
else
    log_fail "No scheduled AIDE scan found"
fi

# 5.3.3 - Ensure cryptographic mechanisms protect audit tools

print_header "5.3.3 - Ensure cryptographic protection of audit tools"
log_manual "Verify cryptographic checksums are used to protect audit tools (e.g., /usr/sbin/auditctl, /usr/sbin/aureport)"

# 5.3 - Configure Integrity Checking (AIDE)

print_header "5.3 - Configure Integrity Checking (AIDE)"

# 5.3.1 - Ensure AIDE is installed

print_header "5.3.1 - Ensure AIDE is installed"
if rpm -q aide &>/dev/null; then
    log_pass "AIDE is installed"
else
    log_fail "AIDE is NOT installed"
fi

# 5.3.2 - Ensure filesystem integrity is regularly checked

print_header "5.3.2 - Ensure AIDE check is scheduled"
if grep -qr aide /etc/cron.* /etc/anacrontab; then
    log_pass "AIDE job is scheduled via cron or anacron"
else
    log_fail "No AIDE cron/anacron job found"
fi

# 5.3.3 - Ensure crypto mechanisms protect audit tools

print_header "5.3.3 - Ensure audit tools are verified by integrity checks"
log_manual "Confirm AIDE or other tool verifies audit binaries and config files for integrity"

# 6.1 - System File Permissions

print_header "6.1 - System File Permissions"

declare -A system_files=(
    ["/etc/passwd"]="644"
    ["/etc/passwd-"]="600"
    ["/etc/group"]="644"
    ["/etc/group-"]="600"
    ["/etc/shadow"]="000"
    ["/etc/shadow-"]="000"
    ["/etc/gshadow"]="000"
    ["/etc/gshadow-"]="000"
    ["/etc/shells"]="644"
)

for file in "${!system_files[@]}"; do
    check_permissions "$file" "${system_files[$file]}"
done

# 6.1.11 - Ensure no world writable files exist

print_header "6.1.11 - Ensure no world-writable files exist"
world_writable=$(find / -xdev -type f -perm -0002 2>/dev/null)
if [ -z "$world_writable" ]; then
    log_pass "No world-writable files found"
else
    log_fail "World-writable files exist:
$world_writable"
fi

# 6.1.12 - Ensure no unowned or ungrouped files exist

print_header "6.1.12 - Ensure no unowned or ungrouped files exist"
unowned=$(find / -xdev -nouser -o -nogroup 2>/dev/null)
if [ -z "$unowned" ]; then
    log_pass "No unowned or ungrouped files found"
else
    log_fail "Unowned or ungrouped files found:
$unowned"
fi

# 6.1.13 - Manual review of SUID/SGID

print_header "6.1.13 - Manual review of SUID/SGID files"
log_manual "Run: find / -xdev \( -perm -4000 -o -perm -2000 \) -type f"

# 6.1.14 - Manual audit of system file permissions

print_header "6.1.14 - Manual audit of system file permissions"
log_manual "Review system file permissions and ownership manually or with tools like rpm -Va"

# 6.2 - Local User and Group Settings

print_header "6.2 - Local User and Group Settings"

# 6.2.1 - Ensure accounts use shadowed passwords

print_header "6.2.1 - Ensure accounts in /etc/passwd use shadowed passwords"
if awk -F: '($2 != "x") {print $1}' /etc/passwd | grep -qvE "^$"; then
    log_fail "Some accounts do not use shadowed passwords"
else
    log_pass "All accounts use shadowed passwords"
fi

# 6.2.2 - Ensure shadow password fields are not empty

print_header "6.2.2 - Ensure shadow password fields are not empty"
if awk -F: '($2 == "" ) { print $1 }' /etc/shadow | grep -qvE "^$"; then
    log_fail "Some shadow entries have empty password fields"
else
    log_pass "No shadow entries with empty password fields"
fi

# 6.2.3 - Ensure all groups in /etc/passwd exist in /etc/group

print_header "6.2.3 - Ensure all groups in passwd exist in group"
bad_groups=$(awk -F: '{ print $4 }' /etc/passwd | while read -r gid; do grep -q ":$gid:" /etc/group || echo "$gid"; done)
if [ -z "$bad_groups" ]; then
    log_pass "All groups referenced in /etc/passwd exist in /etc/group"
else
    log_fail "Orphaned GIDs found in passwd: $bad_groups"
fi

# 6.2.4 - Ensure no duplicate UIDs exist

print_header "6.2.4 - Ensure no duplicate UIDs exist"
if cut -d: -f3 /etc/passwd | sort | uniq -d | grep -qvE "^$"; then
    log_fail "Duplicate UIDs found"
else
    log_pass "No duplicate UIDs"
fi

# 6.2.5 - Ensure no duplicate GIDs exist

print_header "6.2.5 - Ensure no duplicate GIDs exist"
if cut -d: -f3 /etc/group | sort | uniq -d | grep -qvE "^$"; then
    log_fail "Duplicate GIDs found"
else
    log_pass "No duplicate GIDs"
fi

# 6.2.6 - Ensure no duplicate user names exist

print_header "6.2.6 - Ensure no duplicate user names exist"
if cut -d: -f1 /etc/passwd | sort | uniq -d | grep -qvE "^$"; then
    log_fail "Duplicate user names found"
else
    log_pass "No duplicate user names"
fi

# 6.2.7 - Ensure no duplicate group names exist

print_header "6.2.7 - Ensure no duplicate group names exist"
if cut -d: -f1 /etc/group | sort | uniq -d | grep -qvE "^$"; then
    log_fail "Duplicate group names found"
else
    log_pass "No duplicate group names"
fi

# 6.2.8 - Ensure root path integrity

print_header "6.2.8 - Ensure root path integrity"
bad_paths=$(echo $PATH | tr ":" "\n" | grep -E "^\.|^$|//|/$")
if [ -z "$bad_paths" ]; then
    log_pass "Root path integrity is valid"
else
    log_fail "Unsafe entries found in PATH: $bad_paths"
fi

# 6.2.9 - Ensure root is the only UID 0 account

print_header "6.2.9 - Ensure root is the only UID 0 account"
uid_zeros=$(awk -F: '($3 == 0) { print $1 }' /etc/passwd)
if [ "$uid_zeros" == "root" ]; then
    log_pass "Only root has UID 0"
else
    log_fail "Multiple UID 0 accounts found: $uid_zeros"
fi

# 6.2.10 - Ensure local interactive user home directories are configured

print_header "6.2.10 - Ensure home directories exist for interactive users"
users_missing_home=$(awk -F: '($3 >= 1000 && $7 !~ /nologin|false/ && !system($6 " [ -d " $6 " ]")) {print $1}' /etc/passwd)
if [ -z "$users_missing_home" ]; then
    log_pass "All interactive users have home directories"
else
    log_fail "Users without home directories: $users_missing_home"
fi

# 6.2.11 - Ensure local interactive user dot files are restricted

print_header "6.2.11 - Ensure dot files are not group/world writable"
bad_dotfiles=$(find /home -type f -name ".*" -perm /022 2>/dev/null)
if [ -z "$bad_dotfiles" ]; then
    log_pass "No insecure dot files found in home directories"
else
    log_fail "Insecure dot files found:
$bad_dotfiles"
fi
