#!/bin/bash

# CIS RHEL Level 2 Audit Script
echo "RHEL CIS Level 2 Audit Starting..."
echo ""

# Logging functions
log_pass()   { echo "[PASS] $1"; }
log_fail()   { echo "[FAIL] $1"; }
log_manual() { echo "[MANUAL] $1"; }
log_note()   { echo "        - $1"; }
print_header() {
    echo "============================================================"
    echo ">> $1"
    echo "============================================================"
}

# 1.1 - Filesystem Kernel Modules (Level 2 - additional modules)
print_header "1.1 - Filesystem Kernel Modules (Level 2 Checks)"

check_module_disabled() {
    local module="$1"
    print_header "Check Kernel Module: $module"
    result=$(modprobe -n -v "$module" 2>/dev/null)
    if echo "$result" | grep -qE 'install /bin/(true|false)'; then
        log_pass "$module is properly disabled"
        log_note "Result: $result"
    else
        log_fail "$module is NOT disabled"
        log_note "Result: $result"
    fi
}

# Level 2 modules (examples: squashfs and usb-storage)
check_module_disabled "usb-storage"


# 1.1.2 - Filesystem Partition Configuration (Level 2)
print_header "1.1.2 - Filesystem Partition Configuration (Level 2)"

check_mount_option() {
    local mount_point="$1"
    local option="$2"
    print_header "Check if $option is set on $mount_point"
    if mount | grep -E "\s$mount_point\s" | grep -qw "$option"; then
        log_pass "$option is set on $mount_point"
    else
        log_fail "$option is NOT set on $mount_point"
    fi
}

check_partition_exists() {
    local mount_point="$1"
    print_header "Check if $mount_point is a separate partition"
    if mount | grep -qw "on $mount_point "; then
        log_pass "$mount_point is mounted as a separate partition"
    else
        log_fail "$mount_point is NOT a separate partition"
    fi
}

# /tmp
check_partition_exists "/tmp"
check_mount_option "/tmp" "nodev"
check_mount_option "/tmp" "nosuid"
check_mount_option "/tmp" "noexec"

# /dev/shm
check_partition_exists "/dev/shm"
check_mount_option "/dev/shm" "nodev"
check_mount_option "/dev/shm" "nosuid"
check_mount_option "/dev/shm" "noexec"

# /home
check_partition_exists "/home"
check_mount_option "/home" "nodev"
check_mount_option "/home" "nosuid"

# /var
check_partition_exists "/var"
check_mount_option "/var" "nodev"
check_mount_option "/var" "nosuid"

# /var/tmp
check_partition_exists "/var/tmp"
check_mount_option "/var/tmp" "nodev"
check_mount_option "/var/tmp" "nosuid"
check_mount_option "/var/tmp" "noexec"

# /var/log
check_partition_exists "/var/log"
check_mount_option "/var/log" "nodev"
check_mount_option "/var/log" "nosuid"
check_mount_option "/var/log" "noexec"

# /var/log/audit
check_partition_exists "/var/log/audit"
check_mount_option "/var/log/audit" "nodev"
check_mount_option "/var/log/audit" "nosuid"
check_mount_option "/var/log/audit" "noexec"

# 1.2 - Configure Software and Patch Management
print_header "1.2 - Software and Patch Management"

# 1.2.1 - Ensure GPG keys are configured (Manual)
print_header "1.2.1 - Ensure GPG keys are configured"
log_manual "Manually verify that GPG keys are properly configured for all enabled repositories."

# 1.2.2 - Ensure gpgcheck is globally activated
print_header "1.2.2 - Ensure gpgcheck is globally activated"
if grep -R "^gpgcheck=1" /etc/yum.conf /etc/yum.repos.d/*.repo 2>/dev/null | grep -vq "^#"; then
    log_pass "gpgcheck is globally activated"
else
    log_fail "gpgcheck is not enabled in all repo config files"
fi

# 1.2.3 - Ensure repo_gpgcheck is globally activated (Manual)
print_header "1.2.3 - Ensure repo_gpgcheck is globally activated"
log_manual "Review /etc/yum.repos.d/*.repo to ensure 'repo_gpgcheck=1' is set where applicable."

# 1.2.4 - Ensure package manager repositories are configured (Manual)
print_header "1.2.4 - Ensure package manager repositories are configured"
log_manual "Review /etc/yum.repos.d/*.repo to ensure only approved repos are enabled."

# 1.2.5 - Ensure updates, patches, and security software are installed (Manual)
print_header "1.2.5 - Ensure updates and security software are installed"
log_manual "Use: 'yum update --security' or 'dnf updateinfo' to verify recent security patches."

# 1.3 - Configure Secure Boot Settings
print_header "1.3 - Secure Boot Settings"

# 1.3.1 - Ensure bootloader password is set (GRUB2)
print_header "1.3.1 - Ensure bootloader password is set"
if grep -q "^GRUB2_PASSWORD=" /etc/grub.d/40_custom; then
    log_pass "Bootloader password is set in GRUB2 config"
else
    log_fail "Bootloader password is NOT set in /etc/grub.d/40_custom"
fi

# 1.3.2 - Ensure permissions on bootloader config are configured
print_header "1.3.2 - Ensure GRUB config permissions are configured"
check_permissions "/boot/grub2/grub.cfg" "600"

# 1.4 - Additional Process Hardening
print_header "1.4 - Additional Process Hardening"

# 1.4.1 - Ensure ASLR is enabled
print_header "1.4.1 - Ensure address space layout randomization (ASLR) is enabled"
if [ "$(sysctl -n kernel.randomize_va_space)" -eq 2 ]; then
    log_pass "ASLR is enabled (kernel.randomize_va_space = 2)"
else
    log_fail "ASLR is not enabled or set incorrectly"
fi

# 1.4.2 - Ensure ptrace_scope is restricted
print_header "1.4.2 - Ensure ptrace_scope is restricted"
if [ "$(sysctl -n kernel.yama.ptrace_scope 2>/dev/null)" -ge 1 ]; then
    log_pass "ptrace_scope is restricted"
else
    log_fail "ptrace_scope is not restricted or not set"
fi

# 1.4.3 - Ensure core dump backtraces are disabled
print_header "1.4.3 - Ensure core dump backtraces are disabled"
if grep -q "^* hard core 0" /etc/security/limits.conf /etc/security/limits.d/* 2>/dev/null; then
    log_pass "Core dump backtraces are disabled"
else
    log_fail "Core dump backtraces not explicitly disabled"
fi

# 1.4.4 - Ensure core dump storage is disabled
print_header "1.4.4 - Ensure core dump storage is disabled"
if grep -q "^Storage=none" /etc/systemd/coredump.conf 2>/dev/null; then
    log_pass "Core dump storage is disabled"
else
    log_fail "Core dump storage is not set to 'none'"
fi

# 1.5 - Mandatory Access Control (SELinux)
print_header "1.5 - Mandatory Access Control (SELinux)"

# 1.5.1.1 - Ensure SELinux is installed
print_header "1.5.1.1 - Ensure SELinux is installed"
if rpm -q libselinux &>/dev/null; then
    log_pass "SELinux is installed"
else
    log_fail "SELinux is NOT installed"
fi

# 1.5.1.2 - Ensure SELinux is not disabled in GRUB
print_header "1.5.1.2 - Ensure SELinux is not disabled in GRUB"
if grep -q "selinux=0" /etc/default/grub; then
    log_fail "SELinux is disabled in GRUB"
else
    log_pass "SELinux is not disabled in GRUB"
fi

# 1.5.1.3 - Ensure SELinux policy is configured
print_header "1.5.1.3 - Ensure SELinux policy is configured"
if grep -Eq "^SELINUXTYPE=(targeted|mls)" /etc/selinux/config; then
    log_pass "SELinux policy type is valid"
else
    log_fail "Invalid SELinux policy type"
fi

# 1.5.1.4 - Ensure SELinux mode is not disabled
print_header "1.5.1.4 - Ensure SELinux mode is not disabled"
if grep -q "^SELINUX=disabled" /etc/selinux/config; then
    log_fail "SELinux is disabled in config"
else
    log_pass "SELinux is not disabled"
fi

# 1.5.1.5 - Ensure SELinux mode is enforcing
print_header "1.5.1.5 - Ensure SELinux is enforcing"
if grep -q "^SELINUX=enforcing" /etc/selinux/config; then
    log_pass "SELinux is enforcing"
else
    log_fail "SELinux is NOT enforcing"
fi

# 1.5.1.6 - Ensure no unconfined services exist
print_header "1.5.1.6 - Check for unconfined SELinux services"
unconfined=$(ps -eZ | grep unconfined_service_t)
if [ -z "$unconfined" ]; then
    log_pass "No unconfined SELinux services found"
else
    log_fail "Unconfined services found:
$unconfined"
fi

# 1.5.1.7 - Ensure mcstrans is not installed
print_header "1.5.1.7 - Ensure mcstrans is not installed"
if rpm -q mcstrans &>/dev/null; then
    log_fail "mcstrans is installed"
else
    log_pass "mcstrans is NOT installed"
fi

# 1.5.1.8 - Ensure SETroubleshoot is not installed
print_header "1.5.1.8 - Ensure setroubleshoot is not installed"
if rpm -q setroubleshoot &>/dev/null; then
    log_fail "setroubleshoot is installed"
else
    log_pass "setroubleshoot is NOT installed"
fi

# 1.6 - Configure System-Wide Crypto Policies
print_header "1.6 - System-Wide Crypto Policies"

# 1.6.1 - Ensure crypto policy is not set to LEGACY
print_header "1.6.1 - Ensure system crypto policy is not legacy"
current_policy=$(update-crypto-policies --show 2>/dev/null)
if [[ "$current_policy" != "LEGACY" ]]; then
    log_pass "Crypto policy is not LEGACY ($current_policy)"
else
    log_fail "Crypto policy is set to LEGACY"
fi

# 1.6.2 - Ensure SHA1 support is disabled
print_header "1.6.2 - Ensure SHA1 hash/signature support is disabled"
if grep -Eqi "sha1|hmac-sha1" /etc/crypto-policies/back-ends/*; then
    log_fail "SHA1 support appears to be present in backend configs"
else
    log_pass "No SHA1 support detected in backend configs"
fi

# 1.6.3 - Ensure CBC ciphers are disabled for SSH
print_header "1.6.3 - Ensure CBC ciphers are disabled for SSH"
if grep -q "Ciphers" /etc/ssh/sshd_config && grep -q "cbc" /etc/ssh/sshd_config; then
    log_fail "CBC ciphers are present in SSH configuration"
else
    log_pass "No CBC ciphers found in SSH configuration"
fi

# 1.6.4 - Ensure MACs < 128-bit are disabled
print_header "1.6.4 - Ensure MACs with less than 128-bit strength are disabled"
if grep -q "MACs" /etc/ssh/sshd_config && grep -Eqi "hmac-md5|hmac-sha1" /etc/ssh/sshd_config; then
    log_fail "Weak MACs (hmac-md5, hmac-sha1) found in SSH configuration"
else
    log_pass "No weak MACs detected in SSH configuration"
fi

# 1.7 - Configure Command Line Warning Banners
print_header "1.7 - Command Line Warning Banners"

validate_banner_content() {
    local file="$1"
    print_header "Check banner content in $file"
    if [ -f "$file" ]; then
        if grep -qiE "unauthorized|access|prohibited|monitored|warning" "$file"; then
            log_pass "$file contains warning banner content"
        else
            log_fail "$file exists but lacks proper warning language"
        fi
    else
        log_fail "$file does not exist"
    fi
}

# 1.7.1 - motd
validate_banner_content "/etc/motd"

# 1.7.2 - issue (local login)
validate_banner_content "/etc/issue"

# 1.7.3 - issue.net (remote login)
validate_banner_content "/etc/issue.net"

# 1.7.4 to 1.7.6 - Check permissions
check_permissions "/etc/motd" "644"
check_permissions "/etc/issue" "644"
check_permissions "/etc/issue.net" "644"

# 1.8 - Configure GNOME Display Manager
print_header "1.8 - GNOME Display Manager Configuration"

# 1.8.1 - Ensure GNOME is removed
print_header "1.8.1 - Ensure GNOME Display Manager is removed"
if rpm -q gdm &>/dev/null; then
    log_fail "GNOME Display Manager (gdm) is installed"
else
    log_pass "GNOME Display Manager (gdm) is NOT installed"
fi

# 1.8.2 - Ensure GDM login banner is configured
print_header "1.8.2 - Ensure GDM login banner is configured"
banner_file="/etc/dconf/db/gdm.d/01-banner-message"
if [ -f "$banner_file" ] && grep -qE "banner-message-enable=true" "$banner_file"; then
    log_pass "GDM login banner is enabled"
else
    log_fail "GDM login banner is not properly configured"
fi

# 1.8.3 - Ensure disable-user-list is enabled
print_header "1.8.3 - Ensure disable-user-list is enabled"
if grep -q "disable-user-list=true" /etc/dconf/db/gdm.d/* 2>/dev/null; then
    log_pass "disable-user-list is enabled"
else
    log_fail "disable-user-list is NOT enabled"
fi

# 1.8.4 - Ensure screen locks when idle
print_header "1.8.4 - Ensure screen locks when idle"
if grep -q "idle-delay=uint32 900" /etc/dconf/db/* 2>/dev/null; then
    log_pass "Screen lock is set to 15 minutes (900 seconds)"
else
    log_fail "Idle screen lock timeout not properly set"
fi

# 1.8.5 - Ensure screen lock cannot be overridden
print_header "1.8.5 - Ensure screen lock cannot be overridden"
if grep -q "lock-enabled=true" /etc/dconf/db/* 2>/dev/null; then
    log_pass "Screen lock override prevention is configured"
else
    log_fail "Screen lock override prevention is NOT configured"
fi

# 1.8.6 - Ensure auto-mounting of removable media is disabled
print_header "1.8.6 - Ensure automatic mounting of removable media is disabled"
if grep -q "automount=false" /etc/dconf/db/* 2>/dev/null; then
    log_pass "Removable media automounting is disabled"
else
    log_fail "Removable media automounting is NOT disabled"
fi

# 1.8.7 - Ensure automount override is not enabled
print_header "1.8.7 - Ensure automount override is not enabled"
if grep -q "automount-open=false" /etc/dconf/db/* 2>/dev/null; then
    log_pass "Auto-open of mounted devices is disabled"
else
    log_fail "Auto-open override is NOT disabled"
fi

# 1.8.8 - Ensure autorun-never is enabled
print_header "1.8.8 - Ensure autorun-never is enabled"
if grep -q "autorun-never=true" /etc/dconf/db/* 2>/dev/null; then
    log_pass "autorun-never is enabled"
else
    log_fail "autorun-never is NOT enabled"
fi

# 1.8.9 - Ensure autorun override is not enabled
print_header "1.8.9 - Ensure autorun override is not enabled"
if grep -q "autorun=false" /etc/dconf/db/* 2>/dev/null; then
    log_pass "Autorun override is disabled"
else
    log_fail "Autorun override is NOT disabled"
fi

# 1.8.10 - Ensure XDMCP is not enabled
print_header "1.8.10 - Ensure XDMCP is not enabled"
if grep -q "\[xdmcp\]" /etc/gdm/custom.conf && grep -q "Enable=true" /etc/gdm/custom.conf; then
    log_fail "XDMCP is enabled"
else
    log_pass "XDMCP is NOT enabled"
fi

# 2.1 - Configure Time Synchronization
print_header "2.1 - Time Synchronization"

# 2.1.1 - Ensure time synchronization is in use
print_header "2.1.1 - Ensure time synchronization is in use"
if rpm -q chrony &>/dev/null || rpm -q ntp &>/dev/null; then
    log_pass "Time synchronization service is installed"
else
    log_fail "No time synchronization service (chrony/ntp) is installed"
fi

# 2.1.2 - Ensure chrony is configured
print_header "2.1.2 - Ensure chrony is configured"
if grep -q "^server\s" /etc/chrony.conf 2>/dev/null; then
    log_pass "Chrony server is configured"
else
    log_fail "Chrony server configuration not found"
fi

# 2.1.3 - Ensure chrony is not run as root
print_header "2.1.3 - Ensure chrony is not run as root"
if grep -Eq "^user\s+chrony" /etc/chrony.conf 2>/dev/null; then
    log_pass "Chrony is configured to run as non-root user"
else
    log_fail "Chrony is not explicitly configured to run as non-root"
fi

# 2.2 - Configure Special Purpose Services
print_header "2.2 - Special Purpose Services"

declare -a special_services=(
    autofs avahi dhcpd named dnsmasq samba vsftpd dovecot nfs-server ypserv cups     rpcbind rsyncd snmpd telnetd tftpd squid httpd xinetd
)

for service in "${special_services[@]}"; do
    print_header "2.2 - Check service: $service"
    if rpm -q "$service" &>/dev/null; then
        if systemctl is-enabled "$service" &>/dev/null; then
            log_fail "$service is installed and enabled"
        else
            log_pass "$service is installed but disabled"
        fi
    else
        log_pass "$service is NOT installed"
    fi
done

# 2.2.21 - Ensure mail transfer agents are local-only
print_header "2.2.21 - Ensure MTA is configured for local-only"
if netstat -tuln | grep ":25" | grep -qv "127.0.0.1"; then
    log_fail "MTA is listening on external interfaces"
else
    log_pass "MTA is listening only on loopback"
fi

# 2.2.22 - Ensure only approved services listen on interfaces (Manual)
print_header "2.2.22 - Manual review of listening services"
log_manual "Review 'ss -tulnp' or 'netstat -tulnp' output and verify all listening ports are approved"

# 2.3 - Configure Service Clients
print_header "2.3 - Service Clients"

declare -a client_packages=(
    ftp telnet ldap-client nis ypbind tftp
)

for pkg in "${client_packages[@]}"; do
    print_header "2.3 - Check client package: $pkg"
    if rpm -q "$pkg" &>/dev/null; then
        log_fail "$pkg client is installed"
    else
        log_pass "$pkg client is NOT installed"
    fi
done

# 3.1 - Configure Network Devices
print_header "3.1 - Configure Network Devices"

# 3.1.1 - Identify IPv6 status (Manual)
print_header "3.1.1 - Identify IPv6 Status"
log_manual "Check IPv6 status manually via: sysctl net.ipv6.conf.all.disable_ipv6 and /etc/sysctl.conf"

# 3.1.2 - Ensure wireless interfaces are disabled
print_header "3.1.2 - Ensure wireless interfaces are disabled"
if nmcli radio all | grep -q "enabled"; then
    log_fail "Wireless interface(s) are enabled"
else
    log_pass "Wireless interfaces are disabled"
fi

# 3.1.3 - Ensure bluetooth services are not in use
print_header "3.1.3 - Ensure bluetooth services are not in use"
if systemctl is-enabled bluetooth &>/dev/null; then
    log_fail "Bluetooth service is enabled"
else
    log_pass "Bluetooth service is not enabled"
fi

# 3.2 - Configure Network Kernel Modules
print_header "3.2 - Network Kernel Modules"

for module in dccp tipc rds sctp; do
    print_header "Check Kernel Module: $module"
    result=$(modprobe -n -v "$module" 2>/dev/null)
    if echo "$result" | grep -qE 'install /bin/(true|false)'; then
        log_pass "$module is properly disabled"
        log_note "Result: $result"
    else
        log_fail "$module is NOT disabled"
        log_note "Result: $result"
    fi
done

# 3.2 - Configure Network Kernel Modules
print_header "3.2 - Network Kernel Modules"

check_module_disabled() {
    local module="$1"
    print_header "Check Network Kernel Module: $module"
    result=$(modprobe -n -v "$module" 2>/dev/null)
    if echo "$result" | grep -qE 'install /bin/(true|false)'; then
        log_pass "$module is properly disabled"
        log_note "Result: $result"
    else
        log_fail "$module is NOT disabled"
        log_note "Result: $result"
    fi
}

# Disable uncommon or risky network-related modules
check_module_disabled "dccp"
check_module_disabled "tipc"
check_module_disabled "rds"
check_module_disabled "sctp"

# 3.3 - Configure Network Kernel Parameters
print_header "3.3 - Network Kernel Parameters"

check_sysctl() {
    local key="$1"
    local expected="$2"
    print_header "Check sysctl: $key = $expected"
    actual=$(sysctl -n "$key" 2>/dev/null)
    if [ "$actual" == "$expected" ]; then
        log_pass "$key is set to $expected"
    else
        log_fail "$key is set to $actual (expected: $expected)"
    fi
}

# Disable IP forwarding
check_sysctl "net.ipv4.ip_forward" "0"
check_sysctl "net.ipv6.conf.all.forwarding" "0"

# Disable packet redirects
check_sysctl "net.ipv4.conf.all.send_redirects" "0"
check_sysctl "net.ipv4.conf.default.send_redirects" "0"

# Ignore bogus ICMP responses
check_sysctl "net.ipv4.icmp_ignore_bogus_error_responses" "1"

# Ignore ICMP broadcast requests
check_sysctl "net.ipv4.icmp_echo_ignore_broadcasts" "1"

# Do not accept ICMP redirects
check_sysctl "net.ipv4.conf.all.accept_redirects" "0"
check_sysctl "net.ipv4.conf.default.accept_redirects" "0"
check_sysctl "net.ipv6.conf.all.accept_redirects" "0"
check_sysctl "net.ipv6.conf.default.accept_redirects" "0"

# Do not accept secure redirects
check_sysctl "net.ipv4.conf.all.secure_redirects" "0"
check_sysctl "net.ipv4.conf.default.secure_redirects" "0"

# Enable reverse path filtering
check_sysctl "net.ipv4.conf.all.rp_filter" "1"
check_sysctl "net.ipv4.conf.default.rp_filter" "1"

# Do not accept source-routed packets
check_sysctl "net.ipv4.conf.all.accept_source_route" "0"
check_sysctl "net.ipv4.conf.default.accept_source_route" "0"
check_sysctl "net.ipv6.conf.all.accept_source_route" "0"
check_sysctl "net.ipv6.conf.default.accept_source_route" "0"

# Log suspicious packets
check_sysctl "net.ipv4.conf.all.log_martians" "1"
check_sysctl "net.ipv4.conf.default.log_martians" "1"

# Enable TCP SYN cookies
check_sysctl "net.ipv4.tcp_syncookies" "1"

# Disable IPv6 router advertisements
check_sysctl "net.ipv6.conf.all.accept_ra" "0"
check_sysctl "net.ipv6.conf.default.accept_ra" "0"

# 3.4 - Configure Host-Based Firewall
print_header "3.4 - Host-Based Firewall"

# 3.4.1.1 - Ensure nftables is installed
print_header "3.4.1.1 - Ensure nftables is installed"
if rpm -q nftables &>/dev/null; then
    log_pass "nftables is installed"
else
    log_fail "nftables is NOT installed"
fi

# 3.4.1.2 - Ensure only one firewall is enabled
print_header "3.4.1.2 - Ensure a single firewall configuration utility is in use"
enabled_fw=$(systemctl list-unit-files | grep enabled | grep -E 'nftables|iptables|firewalld' | awk '{print $1}')
if [ "$(echo "$enabled_fw" | wc -l)" -eq 1 ]; then
    log_pass "Single firewall utility enabled: $enabled_fw"
else
    log_fail "Multiple firewall utilities are enabled: $enabled_fw"
fi

# 3.4.2.1 - Ensure nftables base chains exist
print_header "3.4.2.1 - Ensure nftables base chains exist"
if nft list ruleset 2>/dev/null | grep -q "hook input"; then
    log_pass "nftables base chains (input) exist"
else
    log_fail "nftables base chains not found"
fi

# 3.4.2.2 - Ensure loopback traffic is configured
print_header "3.4.2.2 - Ensure loopback traffic is allowed"
if nft list ruleset 2>/dev/null | grep -q "iif lo accept"; then
    log_pass "Loopback traffic is allowed"
else
    log_fail "Loopback rule not found"
fi

# 3.4.2.3 - MANUAL: Drop unnecessary services/ports in firewalld
print_header "3.4.2.3 - Drop unnecessary services/ports (Manual)"
log_manual "Review firewalld/nftables to ensure only approved services/ports are allowed"

# 3.4.2.4 - MANUAL: nftables handles established/related connections
print_header "3.4.2.4 - Ensure established connections are allowed (Manual)"
log_manual "Check ruleset includes 'ct state established,related accept'"

# 3.4.2.5 - Ensure default deny policy
print_header "3.4.2.5 - Ensure default deny policy in nftables"
if nft list ruleset 2>/dev/null | grep -q "policy drop"; then
    log_pass "Default deny policy (drop) is set"
else
    log_fail "No default deny policy found in ruleset"
fi

# 4.1 - Configure Job Schedulers
print_header "4.1 - Job Schedulers"

# Check permissions and presence of cron-related files/directories
cron_files=(
    /etc/crontab
    /etc/cron.hourly
    /etc/cron.daily
    /etc/cron.weekly
    /etc/cron.monthly
    /etc/cron.d
)

for file in "${cron_files[@]}"; do
    check_permissions "$file" "600"
done

# 4.1.1.1 - Ensure cron daemon is enabled
print_header "4.1.1.1 - Ensure cron daemon is enabled"
if systemctl is-enabled crond &>/dev/null; then
    log_pass "cron daemon is enabled"
else
    log_fail "cron daemon is NOT enabled"
fi

# 4.1.1.8 - Ensure crontab is restricted to authorized users
print_header "4.1.1.8 - Ensure crontab access is restricted"
if [ -f /etc/cron.allow ]; then
    log_pass "/etc/cron.allow exists - access is restricted"
else
    log_fail "/etc/cron.allow does not exist - access is not restricted"
fi

# 4.1.2.1 - Ensure at access is restricted
print_header "4.1.2.1 - Ensure at access is restricted"
if [ -f /etc/at.allow ]; then
    log_pass "/etc/at.allow exists - access is restricted"
else
    log_fail "/etc/at.allow does not exist - access is not restricted"
fi

# 4.2 - Configure SSH Server
print_header "4.2 - SSH Server Configuration"

check_sshd_param() {
    local param="$1"
    local expected="$2"
    actual=$(grep -i "^$param" /etc/ssh/sshd_config | awk '{print $2}' | tr -d '"')
    print_header "Check SSHD config: $param = $expected"
    if [[ "$actual" == "$expected" ]]; then
        log_pass "$param is set to $expected"
    else
        log_fail "$param is set to '$actual' (expected: $expected)"
    fi
}

check_permissions "/etc/ssh/sshd_config" "600"

# SSHD Parameters
check_sshd_param "PermitRootLogin" "no"
check_sshd_param "PermitEmptyPasswords" "no"
check_sshd_param "ClientAliveInterval" "300"
check_sshd_param "ClientAliveCountMax" "3"
check_sshd_param "LoginGraceTime" "60"
check_sshd_param "MaxAuthTries" "4"
check_sshd_param "MaxSessions" "10"
check_sshd_param "MaxStartups" "10:30:60"
check_sshd_param "UsePAM" "yes"
check_sshd_param "PermitUserEnvironment" "no"
check_sshd_param "IgnoreRhosts" "yes"
check_sshd_param "HostbasedAuthentication" "no"

# Ciphers, MACs, Kex
print_header "Validate SSH cryptographic settings"
if grep -q "^Ciphers" /etc/ssh/sshd_config && grep -vq "cbc" /etc/ssh/sshd_config; then
    log_pass "Strong SSH ciphers are used"
else
    log_fail "Weak ciphers (e.g., CBC) may be configured"
fi

if grep -q "^MACs" /etc/ssh/sshd_config && ! grep -Eqi "hmac-md5|hmac-sha1" /etc/ssh/sshd_config; then
    log_pass "Strong SSH MACs are used"
else
    log_fail "Weak MACs (e.g., hmac-md5, hmac-sha1) found or not defined"
fi

# 4.3 - Configure Privilege Escalation
print_header "4.3 - Privilege Escalation Controls"

# 4.3.1 - Ensure sudo is installed
print_header "4.3.1 - Ensure sudo is installed"
if rpm -q sudo &>/dev/null; then
    log_pass "sudo is installed"
else
    log_fail "sudo is NOT installed"
fi

# 4.3.2 - Ensure sudo uses pty
print_header "4.3.2 - Ensure sudo commands use pty"
if grep -q "^Defaults.*requiretty" /etc/sudoers /etc/sudoers.d/* 2>/dev/null; then
    log_pass "sudo is configured to use pty"
else
    log_fail "sudo does not require pty"
fi

# 4.3.3 - Ensure sudo log file exists
print_header "4.3.3 - Ensure sudo log file is configured"
if grep -q "^Defaults.*logfile=" /etc/sudoers /etc/sudoers.d/* 2>/dev/null; then
    log_pass "sudo log file is configured"
else
    log_fail "No sudo logfile configuration found"
fi

# 4.3.4 - Ensure password is required for sudo
print_header "4.3.4 - Ensure password is required for sudo"
if grep -q "!authenticate" /etc/sudoers /etc/sudoers.d/* 2>/dev/null; then
    log_fail "NOPASSWD found in sudo configuration"
else
    log_pass "Password is required for sudo"
fi

# 4.3.5 - Ensure re-authentication is not globally disabled
print_header "4.3.5 - Ensure re-authentication is not globally disabled"
if grep -q "timestamp_timeout=-1" /etc/sudoers /etc/sudoers.d/* 2>/dev/null; then
    log_fail "Re-authentication is disabled (timestamp_timeout = -1)"
else
    log_pass "Re-authentication is not globally disabled"
fi

# 4.3.6 - Ensure sudo timeout is configured
print_header "4.3.6 - Ensure sudo authentication timeout is configured"
if grep -q "timestamp_timeout=" /etc/sudoers /etc/sudoers.d/* 2>/dev/null; then
    log_pass "Sudo timeout is explicitly set"
else
    log_fail "No sudo timeout found"
fi

# 4.3.7 - Ensure access to su is restricted
print_header "4.3.7 - Ensure access to 'su' is restricted"
if grep -q "^auth.*required.*pam_wheel.so" /etc/pam.d/su; then
    log_pass "Access to 'su' is restricted via pam_wheel"
else
    log_fail "'su' access is NOT restricted"
fi

# 4.4 - Configure Pluggable Authentication Modules (PAM)
print_header "4.4 - PAM Configuration"

# 4.4.1.1 - Ensure latest pam is installed
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

# 4.4.2.1 - Ensure authselect profile includes pam modules
print_header "4.4.2.1 - Ensure active authselect profile includes pam modules"
if authselect current | grep -q "with-faillock"; then
    log_pass "authselect includes pam faillock module"
else
    log_fail "authselect profile does not include pam faillock module"
fi

# 4.4.2.2 - Ensure pam_faillock is enabled
print_header "4.4.2.2 - Ensure pam_faillock is enabled"
if grep -q pam_faillock /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null; then
    log_pass "pam_faillock is configured"
else
    log_fail "pam_faillock is NOT configured"
fi

# 4.4.2.3 - Ensure pam_pwquality is enabled
print_header "4.4.2.3 - Ensure pam_pwquality is enabled"
if grep -q pam_pwquality /etc/pam.d/system-auth 2>/dev/null; then
    log_pass "pam_pwquality is configured"
else
    log_fail "pam_pwquality is NOT configured"
fi

# 4.4.2.4 - Ensure pam_pwhistory is enabled
print_header "4.4.2.4 - Ensure pam_pwhistory is enabled"
if grep -q pam_pwhistory /etc/pam.d/system-auth 2>/dev/null; then
    log_pass "pam_pwhistory is configured"
else
    log_fail "pam_pwhistory is NOT configured"
fi

# 4.4.2.5 - Ensure pam_unix is enabled
print_header "4.4.2.5 - Ensure pam_unix is enabled"
if grep -q pam_unix /etc/pam.d/system-auth 2>/dev/null; then
    log_pass "pam_unix is configured"
else
    log_fail "pam_unix is NOT configured"
fi

# 4.5 - User Accounts and Environment
print_header "4.5 - User Accounts and Environment"

# 4.5.1.1 - Ensure strong hashing algorithm is configured
print_header "4.5.1.1 - Ensure strong password hashing algorithm is configured"
if grep -q "^ENCRYPT_METHOD SHA512" /etc/login.defs; then
    log_pass "Strong password hashing algorithm (SHA512) is configured"
else
    log_fail "SHA512 hashing not configured in /etc/login.defs"
fi

# 4.5.1.2 - Ensure password expiration is 365 days or less
print_header "4.5.1.2 - Ensure password expiration <= 365 days"
max_days=$(grep -E "^PASS_MAX_DAYS" /etc/login.defs | awk '{print $2}')
if [ "$max_days" -le 365 ] 2>/dev/null; then
    log_pass "Password expiration is set to $max_days days"
else
    log_fail "Password expiration exceeds 365 days"
fi

# 4.5.1.3 - Ensure password warning >= 7 days
print_header "4.5.1.3 - Ensure password expiration warning >= 7 days"
warn_days=$(grep -E "^PASS_WARN_AGE" /etc/login.defs | awk '{print $2}')
if [ "$warn_days" -ge 7 ] 2>/dev/null; then
    log_pass "Password warning age is $warn_days days"
else
    log_fail "Password warning age is less than 7 days"
fi

# 4.5.1.4 - Ensure inactive lock <= 30 days
print_header "4.5.1.4 - Ensure inactive password lock <= 30 days"
if useradd -D | grep -q "INACTIVE=30"; then
    log_pass "Default inactive lock is 30 days"
else
    log_fail "Default inactive lock is not set to 30 days"
fi

# 4.5.1.5 - Ensure all users have changed password in the past
print_header "4.5.1.5 - Ensure all users have changed passwords in the past"
if awk -F: '($2 != "*" && $2 != "!" && $3 < 1000 && $1 != "root") { print $1 }' /etc/shadow | grep -qv '^$'; then
    log_fail "Some users have not changed passwords"
else
    log_pass "All users have a password change date set"
fi

# 4.5.2.1 - Ensure root default group is GID 0
print_header "4.5.2.1 - Ensure root default group is GID 0"
if grep -q "^root:.*:0:0:" /etc/passwd; then
    log_pass "Root default group is GID 0"
else
    log_fail "Root does not have GID 0"
fi

# 4.5.2.2 - Ensure root umask is configured
print_header "4.5.2.2 - Ensure root umask is configured"
if grep -Eq "^umask\s+0?(077|027)" /root/.bashrc /root/.profile 2>/dev/null; then
    log_pass "Root umask is set securely"
else
    log_fail "Root umask is not configured securely"
fi

# 4.5.2.3 - Ensure system accounts are secured
print_header "4.5.2.3 - Ensure system accounts are secured"
unsecured_sys_accts=$(awk -F: '($3<1000 && $1!="root" && $7!="/sbin/nologin" && $7!="/bin/false") {print $1}' /etc/passwd)
if [ -z "$unsecured_sys_accts" ]; then
    log_pass "All system accounts are secured"
else
    log_fail "Unsecured system accounts found: $unsecured_sys_accts"
fi

# 4.5.2.4 - Ensure root password is set
print_header "4.5.2.4 - Ensure root password is set"
if awk -F: '($1 == "root" && $2 !~ /^[*!]$/)' /etc/shadow | grep -q '^'; then
    log_pass "Root password is set"
else
    log_fail "Root password is not set"
fi

# 4.5.3.1 - Ensure nologin is not listed in /etc/shells
print_header "4.5.3.1 - Ensure nologin is not listed in /etc/shells"
if grep -q "/sbin/nologin" /etc/shells; then
    log_fail "/sbin/nologin should not be in /etc/shells"
else
    log_pass "/sbin/nologin is not listed in /etc/shells"
fi

# 4.5.3.2 - Ensure user shell timeout is set
print_header "4.5.3.2 - Ensure default user shell timeout is configured"
if grep -q "TMOUT=900" /etc/profile /etc/bashrc /etc/profile.d/* 2>/dev/null; then
    log_pass "Shell timeout (TMOUT) is set"
else
    log_fail "Shell timeout (TMOUT) is not configured"
fi

# 4.5.3.3 - Ensure default user umask is set
print_header "4.5.3.3 - Ensure default user umask is set"
if grep -Eq "umask\s+0?(027|077)" /etc/bashrc /etc/profile /etc/profile.d/* 2>/dev/null; then
    log_pass "Default user umask is configured"
else
    log_fail "Default user umask is not configured"
fi

# 5.1 - Configure Logging
print_header "5.1 - Logging Configuration"

# 5.1.1.1 - Ensure rsyslog is installed
print_header "5.1.1.1 - Ensure rsyslog is installed"
if rpm -q rsyslog &>/dev/null; then
    log_pass "rsyslog is installed"
else
    log_fail "rsyslog is NOT installed"
fi

# 5.1.1.2 - Ensure rsyslog service is enabled (Manual)
print_header "5.1.1.2 - Ensure rsyslog service is enabled"
log_manual "Manually verify: systemctl is-enabled rsyslog"

# 5.1.1.3 - Ensure journald forwards to rsyslog (Manual)
print_header "5.1.1.3 - Ensure journald forwards to rsyslog"
log_manual "Check /etc/systemd/journald.conf for 'ForwardToSyslog=yes'"

# 5.1.1.4 - Ensure rsyslog file permissions are configured
print_header "5.1.1.4 - Ensure rsyslog default file permissions"
if grep -q "^$FileCreateMode 0640" /etc/rsyslog.conf /etc/rsyslog.d/* 2>/dev/null; then
    log_pass "rsyslog file permissions set to 0640"
else
    log_fail "rsyslog file permissions not set to 0640"
fi

# 5.1.1.5 to 5.1.1.7 - Manual logging and remote configuration checks
print_header "5.1.1.5 - Ensure logging is configured (Manual)"
log_manual "Review /etc/rsyslog.conf and /etc/rsyslog.d/* for appropriate logging rules"

print_header "5.1.1.6 - Ensure logs are sent to remote host (Manual)"
log_manual "Check for remote log destination entries in rsyslog config"

print_header "5.1.1.7 - Ensure rsyslog is not listening for remote logs"
if grep -qE "^\$ModLoad imudp|^\$ModLoad imtcp" /etc/rsyslog.conf /etc/rsyslog.d/* 2>/dev/null; then
    log_fail "rsyslog is configured to receive remote logs"
else
    log_pass "rsyslog is NOT configured to receive remote logs"
fi

# 5.2 - Configure System Accounting (auditd)
print_header "5.2 - System Accounting (auditd)"

# 5.2.1.1 - Ensure audit is installed
print_header "5.2.1.1 - Ensure audit is installed"
if rpm -q audit &>/dev/null; then
    log_pass "audit is installed"
else
    log_fail "audit is NOT installed"
fi

# 5.2.1.2 - Ensure audit is enabled at boot
print_header "5.2.1.2 - Ensure audit is enabled at boot"
if grep -q "audit=1" /etc/default/grub /boot/grub2/grub.cfg; then
    log_pass "audit=1 is set in GRUB configuration"
else
    log_fail "audit=1 is NOT set in GRUB configuration"
fi

# 5.2.1.3 - Ensure audit_backlog_limit is sufficient
print_header "5.2.1.3 - Ensure audit_backlog_limit is set"
if grep -q "audit_backlog_limit=" /etc/default/grub /boot/grub2/grub.cfg; then
    log_pass "audit_backlog_limit is set"
else
    log_fail "audit_backlog_limit is NOT set"
fi

# 5.2.1.4 - Ensure auditd service is enabled
print_header "5.2.1.4 - Ensure auditd service is enabled"
if systemctl is-enabled auditd &>/dev/null; then
    log_pass "auditd service is enabled"
else
    log_fail "auditd service is NOT enabled"
fi

# 5.2.2.1 - Ensure audit log storage size is configured
print_header "5.2.2.1 - Ensure audit log storage size is configured"
if grep -q "^max_log_file =" /etc/audit/auditd.conf; then
    log_pass "Audit max_log_file is configured"
else
    log_fail "Audit max_log_file is NOT configured"
fi

# 5.2.2.2 - Ensure audit logs are not automatically deleted
print_header "5.2.2.2 - Ensure audit logs are not automatically deleted"
if grep -q "^max_log_file_action = keep_logs" /etc/audit/auditd.conf; then
    log_pass "Audit logs are retained (keep_logs)"
else
    log_fail "Audit logs may be deleted automatically"
fi

# 5.2.2.3 - Ensure system is disabled on audit log full
print_header "5.2.2.3 - Ensure system halts when audit logs are full"
if grep -q "^admin_space_left_action = halt" /etc/audit/auditd.conf; then
    log_pass "System configured to halt when audit logs are full"
else
    log_fail "System is NOT configured to halt on full audit logs"
fi

# 5.2.2.4 - Ensure system warns when audit logs are low
print_header "5.2.2.4 - Ensure system warns on low audit log space"
if grep -q "^space_left_action = email" /etc/audit/auditd.conf; then
    log_pass "System is configured to email on low audit space"
else
    log_fail "System does NOT notify on low audit space"
fi

# 5.2.3 - Configure auditd rules
print_header "5.2.3 - auditd Rules Configuration"

# These rules vary by system usage and must be reviewed manually
log_manual "Verify /etc/audit/rules.d/*.rules or /etc/audit/audit.rules includes:"
log_manual "- sudoers and sudo.log file modifications"
log_manual "- changes to date/time, network environment, and MAC settings"
log_manual "- use of privileged commands"
log_manual "- user/group modifications and login/logout events"
log_manual "- DAC permission modifications and session initiation"
log_manual "- mounts, chcon, setfacl, usermod, and module loading events"
log_manual "- immutability of rules and sync between disk and runtime rules"

# 5.2.4 - auditd File Access Controls
print_header "5.2.4 - auditd File Access Controls"

check_permissions "/var/log/audit" "750"
check_permissions "/var/log/audit/audit.log" "640"

check_owner_group() {
    file="$1"
    expected_user="$2"
    expected_group="$3"
    actual_user=$(stat -c %U "$file")
    actual_group=$(stat -c %G "$file")
    print_header "Check ownership of $file"
    if [[ "$actual_user" == "$expected_user" && "$actual_group" == "$expected_group" ]]; then
        log_pass "$file ownership is correct ($expected_user:$expected_group)"
    else
        log_fail "$file ownership is $actual_user:$actual_group (expected: $expected_user:$expected_group)"
    fi
}

check_owner_group "/var/log/audit" "root" "root"
check_owner_group "/var/log/audit/audit.log" "root" "root"

check_permissions "/etc/audit/auditd.conf" "640"
check_owner_group "/etc/audit/auditd.conf" "root" "root"

check_permissions "/etc/audit/rules.d" "755"
check_owner_group "/etc/audit/rules.d" "root" "root"

# Check tools like auditctl
check_permissions "/sbin/auditctl" "755"
check_owner_group "/sbin/auditctl" "root" "root"

# 5.3 - Configure Integrity Checking (AIDE)
print_header "5.3 - Configure Integrity Checking (AIDE)"

# 5.3.1 - Ensure AIDE is installed
print_header "5.3.1 - Ensure AIDE is installed"
if rpm -q aide &>/dev/null; then
    log_pass "AIDE is installed"
else
    log_fail "AIDE is NOT installed"
fi

# 5.3.2 - Ensure AIDE check is scheduled
print_header "5.3.2 - Ensure AIDE check is scheduled"
if grep -qr "aide" /etc/cron*; then
    log_pass "AIDE check is scheduled via cron"
else
    log_fail "No scheduled AIDE job found"
fi

# 5.3.3 - Ensure cryptographic integrity of audit tools
print_header "5.3.3 - Ensure cryptographic protection of audit tools"
log_manual "Review AIDE rules or other file integrity tools to confirm audit binaries are covered"

# 6 - System Maintenance
print_header "6 - System Maintenance"

# 6.1 - System File Permissions
print_header "6.1 - System File Permissions"
check_permissions "/etc/passwd" "644"
check_permissions "/etc/passwd-" "600"
check_permissions "/etc/group" "644"
check_permissions "/etc/group-" "600"
check_permissions "/etc/shadow" "000"
check_permissions "/etc/shadow-" "000"
check_permissions "/etc/gshadow" "000"
check_permissions "/etc/gshadow-" "000"
check_permissions "/etc/shells" "644"

# 6.1.11 - Ensure no world-writable files
print_header "6.1.11 - Ensure no world-writable files exist"
if find / -xdev -type f -perm -0002 ! -path "/proc/*" 2>/dev/null | grep -q .; then
    log_fail "World-writable files found"
else
    log_pass "No world-writable files found"
fi

# 6.1.12 - Ensure no unowned or ungrouped files exist
print_header "6.1.12 - Ensure no unowned or ungrouped files exist"
if find / -xdev -nouser -o -nogroup 2>/dev/null | grep -q .; then
    log_fail "Unowned or ungrouped files found"
else
    log_pass "No unowned or ungrouped files found"
fi

# 6.1.13 - MANUAL: Review SUID/SGID files
print_header "6.1.13 - Review SUID/SGID files (Manual)"
log_manual "Run: find / -xdev \( -perm -4000 -o -perm -2000 \) -type f"

# 6.1.14 - MANUAL: Audit file permissions
print_header "6.1.14 - Audit system file permissions (Manual)"
log_manual "Ensure regular audits are scheduled for system file permissions"

# 6.2 - Local User and Group Settings
print_header "6.2 - Local User and Group Settings"
log_manual "Covered by Section 4.5 – accounts, passwords, and shell configs"
