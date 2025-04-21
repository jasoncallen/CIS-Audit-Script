#!/usr/bin/env bash

# Ubuntu CIS Level 2 Audit Script (Plain Output)
# Run with sudo or as root

OUTPUT_FILE="cis_level2_report.txt"
> "$OUTPUT_FILE"

PASS_COUNT=0
FAIL_COUNT=0
MANUAL_COUNT=0

# Logging functions (plain ASCII for compatibility)
print_header() {
    local title="$1"
    echo -e "\n============================================================" | tee -a "$OUTPUT_FILE"
    echo -e ">> $title" | tee -a "$OUTPUT_FILE"
    echo -e "============================================================" | tee -a "$OUTPUT_FILE"
}

log_pass() {
    ((PASS_COUNT++))
    echo -e "[PASS]   $1" | tee -a "$OUTPUT_FILE"
}

log_fail() {
    ((FAIL_COUNT++))
    echo -e "[FAIL]   $1" | tee -a "$OUTPUT_FILE"
}

log_manual() {
    ((MANUAL_COUNT++))
    echo -e "[MANUAL] $1" | tee -a "$OUTPUT_FILE"
}

log_note() {
    echo -e "         $1" | tee -a "$OUTPUT_FILE"
}

# Audit Functions

check_sysctl_value() {
    local key="$1"
    local expected="$2"
    print_header "Checking sysctl: $key"
    local current
    current=$(sysctl -n "$key" 2>/dev/null)

    if [ "$current" == "$expected" ]; then
        log_pass "$key is set to $expected"
    else
        log_fail "$key is $current (Expected: $expected)"
    fi
}

check_password_policy() {
    local file="$1"
    local key="$2"
    local expected="$3"
    print_header "Checking Password Policy: $key in $file"

    local current
    current=$(grep -E "^\s*$key" "$file" | awk '{print $2}' | head -1)

    if [ "$current" == "$expected" ]; then
        log_pass "$key is $expected in $file"
    else
        log_fail "$key is $current (Expected: $expected)"
    fi
}

check_file_value() {
    local file="$1"
    local key="$2"
    local expected="$3"
    print_header "Checking Config File: $file for $key"

    local result
    result=$(grep -E "^\s*$key" "$file" 2>/dev/null | awk '{print $2}' | head -1)

    if [ "$result" == "$expected" ]; then
        log_pass "$key is $expected in $file"
    else
        log_fail "$key is $result (Expected: $expected)"
    fi
}

check_shadow_permissions() {
    print_header "Checking /etc/shadow File Permissions"
    perms=$(stat -c "%a" /etc/shadow)
    owner=$(stat -c "%U:%G" /etc/shadow)

    if [ "$perms" == "640" ] && [ "$owner" == "root:shadow" ]; then
        log_pass "/etc/shadow permissions and ownership are secure"
    else
        log_fail "/etc/shadow permissions: $perms or ownership: $owner incorrect (Expected: 640 and root:shadow)"
    fi
}

# Main Audit

echo "Ubuntu CIS Level 2 Audit Starting..." | tee -a "$OUTPUT_FILE"

# 1.6.1 - Restrict Core Dumps
check_file_value "/etc/security/limits.conf" "* hard core" "0"

# 1.6.2 - Enable AppArmor (mandatory access control)
print_header "Check AppArmor Status"
if systemctl is-active apparmor &>/dev/null; then
    log_pass "AppArmor is active"
else
    log_fail "AppArmor is not active"
fi

# 1.8.x - GDM or login banners
check_permissions "/etc/gdm3/greeter.dconf-defaults" "644"  # If GDM is installed
check_permissions "/etc/motd" "644"
check_permissions "/etc/issue" "644"
check_permissions "/etc/issue.net" "644"

# 3.x - Network Parameters (host and router)
check_sysctl_value "net.ipv4.ip_forward" "0"
check_sysctl_value "net.ipv6.conf.all.forwarding" "0"

# 3.3.x - Secure ICMP
check_sysctl_value "net.ipv4.icmp_echo_ignore_broadcasts" "1"
check_sysctl_value "net.ipv4.icmp_ignore_bogus_error_responses" "1"

# 4.1.x - Filesystem Integrity (manual setup often required)
print_header "Check AIDE Integrity Tool"
if dpkg -s aide &>/dev/null; then
    log_pass "AIDE is installed"
else
    log_fail "AIDE is not installed"
fi

# 5.3.x - Password Policies
check_password_policy "/etc/login.defs" "PASS_MAX_DAYS" "90"
check_password_policy "/etc/login.defs" "PASS_MIN_DAYS" "7"
check_password_policy "/etc/login.defs" "PASS_WARN_AGE" "7"

# 5.4.x - Check /etc/shadow permissions
check_shadow_permissions

# 6.2.x - Check no world writable home directories
print_header "Check for World-Writable Home Directories"
bad_dirs=$(awk -F: '{if ($7 != "/usr/sbin/nologin" && $6 ~ /^\/home/) print $6}' /etc/passwd | xargs -I{} find {} -type d -perm -0002 2>/dev/null)
if [ -z "$bad_dirs" ]; then
    log_pass "No world-writable home directories"
else
    log_fail "World-writable home directories found"
    log_note "$bad_dirs"
fi

# Summary
print_header "Audit Summary"
echo -e "[PASS]   $PASS_COUNT" | tee -a "$OUTPUT_FILE"
echo -e "[FAIL]   $FAIL_COUNT" | tee -a "$OUTPUT_FILE"
echo -e "[MANUAL] $MANUAL_COUNT" | tee -a "$OUTPUT_FILE"
echo -e "\nAudit complete. Detailed results saved to: $OUTPUT_FILE" | tee -a "$OUTPUT_FILE"
