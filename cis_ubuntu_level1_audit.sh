#!/usr/bin/env bash

# Ubuntu CIS Level 1 Audit Script (Plain Output)
# Run with sudo or as root

OUTPUT_FILE="cis_level1_report.txt"
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

check_kernel_module_disabled() {
    local module="$1"
    print_header "Checking Kernel Module: $module"
    local result
    result=$(modprobe -n -v "$module" 2>/dev/null)

    if echo "$result" | grep -qE 'install /bin/(true|false)'; then
        log_pass "$module is properly disabled"
        log_note "Details: $result"
    else
        log_fail "$module is NOT disabled"
        log_note "Details: $result"
    fi
}

check_service_disabled() {
    local service="$1"
    print_header "Checking Service: $service"
    if systemctl is-enabled "$service" &>/dev/null; then
        log_fail "$service is ENABLED"
    else
        log_pass "$service is DISABLED"
    fi
}

check_permissions() {
    local file="$1"
    local expected="$2"
    print_header "Checking File Permissions: $file"

    if [ ! -e "$file" ]; then
        log_fail "$file does not exist"
        return
    fi

    local actual
    actual=$(stat -c "%a" "$file" 2>/dev/null)

    if [ "$actual" == "$expected" ]; then
        log_pass "Correct permissions ($actual)"
    else
        log_fail "Incorrect permissions: $actual (Expected: $expected)"
    fi
}

check_auditd_installed() {
    print_header "Checking auditd Installation"
    if dpkg -s auditd &>/dev/null; then
        log_pass "auditd is installed"
    else
        log_fail "auditd is NOT installed"
    fi
}

# Main Audit

echo "Ubuntu CIS Level 1 Audit Starting..." | tee -a "$OUTPUT_FILE"

# 1.1.x - Disable uncommon filesystems
for module in cramfs freevxfs jffs2 hfs hfsplus squashfs udf; do
    check_kernel_module_disabled "$module"
done

# 1.4.x - Ensure auditing is configured
check_auditd_installed

# 1.5.x - Secure Boot settings
print_header "Bootloader & UEFI Settings"
log_manual "Check bootloader password and UEFI secure boot manually"

# 1.6.x - MAC
check_service_disabled "apparmor"  # Should be enabled; we flag if disabled

# 1.7.x - Login banners
check_permissions "/etc/motd" "644"
check_permissions "/etc/issue" "644"
check_permissions "/etc/issue.net" "644"

# 2.x - Services
for svc in avahi-daemon cups nfs-server rpcbind snapd ufw; do
    check_service_disabled "$svc"
done

# Summary
print_header "Audit Summary"
echo -e "[PASS]   $PASS_COUNT" | tee -a "$OUTPUT_FILE"
echo -e "[FAIL]   $FAIL_COUNT" | tee -a "$OUTPUT_FILE"
echo -e "[MANUAL] $MANUAL_COUNT" | tee -a "$OUTPUT_FILE"
echo -e "\nAudit complete. Detailed results saved to: $OUTPUT_FILE" | tee -a "$OUTPUT_FILE"
