#!/usr/bin/env bash

# CIS_RHEL_9_Audit.sh
# Version: 1.0
# Author: Jason Callen
# Description: Audits RHEL 9 system for CIS Level 1 Automated compliance
# Date: 2025-06-01

PASS_COUNT=0
FAIL_COUNT=0
log_pass() { ((PASS_COUNT++)); echo -e "[PASS]   $1" | tee -a "$OUTPUT_FILE"; }
log_fail() { ((FAIL_COUNT++)); echo -e "[FAIL]   $1" | tee -a "$OUTPUT_FILE" | tee -a "$FAIL_REPORT"; }
log_note() { echo "        - $1"; }
OUTPUT_FILE="cis_level1_report_rhel.txt"
> "$OUTPUT_FILE"
FAIL_REPORT="cis_level1_failed_report_rhel.txt"
> "$FAIL_REPORT"
LOGGING_METHOD="unknown"

summary(){
    print_header "Audit Summary"
    echo -e "[PASS] $PASS_COUNT"
    echo -e "[FAIL] $FAIL_COUNT"
    echo -e "\nAudit complete. Detailed results saved to: $OUTPUT_FILE" | tee -a "$OUTPUT_FILE"
    echo -e "\nFailed tests saved to :$FAIL_REPORT"
}

print_header() {
    local title="$1"
    echo -e "\n============================================================" | tee -a "$OUTPUT_FILE"
    echo -e ">> $title" | tee -a "$OUTPUT_FILE"
    echo -e "============================================================" | tee -a "$OUTPUT_FILE"
}

check_kernel_module() {
  local l_mod_name="$1"        # module name (e.g., cramfs)
  local l_mod_type="$2"        # module type (e.g., fs, drivers)
  print_header "1.1.1.X - Configure Filesystem Kernel Module: $l_mod_name"

  l_output3=""
  l_dl=""
  unset a_output a_output2
  l_mod_path="$(readlink -f /lib/modules/**/kernel/$l_mod_type | sort -u)"

  f_module_chk() {
    l_dl="y"
    a_showconfig=()
    while IFS= read -r l_showconfig; do
      a_showconfig+=("$l_showconfig")
    done < <(modprobe --showconfig | grep -P -- '\b(install|blacklist)\h+'"${l_mod_name//-/_}"'\b')

    if ! lsmod | grep "$l_mod_name" &> /dev/null; then
      a_output+=("  - kernel module: \"$l_mod_name\" is not loaded")
    else
      a_output2+=("  - kernel module: \"$l_mod_name\" is loaded")
    fi

    if grep -Pq -- '\binstall\h+'"${l_mod_name//-/_}"'\h+\/bin\/(true|false)\b' <<< "${a_showconfig[*]}"; then
      a_output+=("  - kernel module: \"$l_mod_name\" is not loadable")
    else
      a_output2+=("  - kernel module: \"$l_mod_name\" is loadable")
    fi

    if grep -Pq -- '\bblacklist\h+'"${l_mod_name//-/_}"'\b' <<< "${a_showconfig[*]}"; then
      a_output+=("  - kernel module: \"$l_mod_name\" is deny listed")
    else
      a_output2+=("  - kernel module: \"$l_mod_name\" is not deny listed")
    fi
  }

  for l_mod_base_directory in $l_mod_path; do
    if [ -d "$l_mod_base_directory/${l_mod_name/-/\/}" ] && [ -n "$(ls -A "$l_mod_base_directory/${l_mod_name/-/\/}")" ]; then
      l_output3="$l_output3\n  - \"$l_mod_base_directory\""
      [[ "$l_mod_name" =~ overlay ]] && l_mod_name="${l_mod_name::-2}"
      [ "$l_dl" != "y" ] && f_module_chk
    else
      a_output+=(" - kernel module: \"$l_mod_name\" doesn't exist in \"$l_mod_base_directory\"")
    fi
  done

  [ -n "$l_output3" ] && echo -e "\n\n -- INFO --\n - module: \"$l_mod_name\" exists in:$l_output3"

  if [ "${#a_output2[@]}" -le 0 ]; then
    printf '%s\n' "" "- Audit Result:" "  ** PASS **" "${a_output[@]}"
    log_pass "$l_mod_name is properly disabled"
  else
    printf '%s\n' "" "- Audit Result:" "  ** FAIL **" " - Reason(s) for audit failure:" "${a_output2[@]}"
    [ "${#a_output[@]}" -gt 0 ] && printf '%s\n' "- Correctly set:" "${a_output[@]}"
    log_fail "$l_mod_name IS NOT disabled"
  fi
}

check_mount_and_options() {
    local mount_point="$1"
    print_header "1.1.2.X - Configure Filesystem Partions: $mount_point"
    # Try to get the mount options for mount_point
    local mount_opts
    mount_opts=$(findmnt -kn "$mount_point" 2>/dev/null)

    if [ -z "$mount_opts" ]; then
        log_pass "$mount_point is not a separate partition, no option enforcement required"
        return
    fi

    # If mount_point is mounted, check required options
    local missing_opts=()

    for opt in nodev nosuid noexec; do
        if ! echo "$mount_opts" | grep -qw "$opt"; then
            missing_opts+=("$opt")
        fi
    done

    if [ ${#missing_opts[@]} -eq 0 ]; then
        log_pass "$mount_point is mounted with required options: nodev, nosuid, noexec"
    else
        log_fail "$mount_point is mounted BUT missing: ${missing_opts[*]}"
    fi
}

gpgcheck() {
   print_header "1.2.1.2 - Configure Package Repositories"
    if grep -Pi -- '^\h*gpgcheck\h*=\h*(1|true|yes)\b' /etc/dnf/dnf.conf; then
        log_pass "gpgcheck is enabled in dnf.conf"
    else
        grep -Pris -- '^\h*gpgcheck\h*=\h*(0|[2-9]|[1-9][0-9]+|false|no)\b' /etc/yum.repos.d/
        log_fail "gpgcheck is NOT properly enabled in dnf.conf"
    fi
}

check_libselinux_installed() {
   print_header "1.3.1.1 - Ensure SELinux is installed"
    if rpm -q libselinux; then
        log_pass "libselinux is installed"
    else
        log_fail "libselinux is NOT installed"
    fi
}

check_selinux_disabled() {
   print_header "1.3.1.2 - Ensure SELinux is not disabled in bootloader"
    if grubby --info=ALL | grep -Po '(selinux|enforcing)=0\b' > /dev/null; then
        log_fail "SELinux IS disabled via GRUB boot parameters"
    else
        log_pass "SELinux is not disabled via GRUB (compliant)"
    fi
}

check_selinuxtype() {
    print_header "1.3.1.3 - Ensure SELinux policy is configured"
    if grep -Eq '^\s*SELINUXTYPE=(targeted|mls)\b' /etc/selinux/config; then
        # Extract current loaded policy
        loaded_policy=$(sestatus | grep 'Loaded policy name' | awk '{print $NF}')
        
        if [[ "$loaded_policy" == "targeted" || "$loaded_policy" == "mls" ]]; then
            log_pass "SELINUXTYPE is set to '$loaded_policy' and policy is properly loaded"
        else
            log_fail "SELINUXTYPE is set to targeted/mls in config BUT loaded policy is '$loaded_policy'"
        fi
    else
        log_fail "SELINUXTYPE is NOT set to targeted or mls in /etc/selinux/config"
    fi
}

check_selinux_mode() {
    print_header "1.3.1.4 - Ensure the SELinux is not disabled"
    config_mode=$(grep -Ei '^\s*SELINUX=(enforcing|permissive)' /etc/selinux/config | awk -F= '{print tolower($2)}')

    # Get current runtime mode
    runtime_mode=$(getenforce | tr '[:upper:]' '[:lower:]')

    if [[ "$config_mode" == "enforcing" || "$config_mode" == "permissive" ]]; then
        if [[ "$runtime_mode" == "$config_mode" ]]; then
            log_pass "SELinux config mode ($config_mode) matches runtime mode ($runtime_mode)"
        else
            log_fail "Mismatch: SELinux config mode is '$config_mode' BUT runtime is '$runtime_mode'"
        fi
    else
        log_fail "SELinux config is NOT set to enforcing or permissive (found: '$config_mode')"
    fi
}

check_selinux_tools_not_installed() {
    local package="$1"
    print_header "1.3.1.4 - Ensure '$package' the is not installed"
    if rpm -q "$package"; then
      log_fail "$package IS installed"
    else
      log_pass "$package is not installed (compliant)"
    fi
}

check_grub_password_set() {
    local grub_password_file
    print_header "1.4.1 - Ensure bootlader password is set"
    grub_password_file="$(find /boot -type f -name 'user.cfg' ! -empty 2>/dev/null)"

    if [ -f "$grub_password_file" ]; then
        if grep -q '^GRUB2_PASSWORD=' "$grub_password_file"; then
            log_pass "GRUB2 password is set in $grub_password_file"
        else
            log_fail "GRUB2 password file exists BUT no password entry found"
        fi
    else
        log_fail "NO non-empty user.cfg file found in /boot (GRUB2 password likely not set)"
    fi
}

check_bootloader(){ 
   l_output="" l_output2=""
   print_header "1.4.2 - Ensure access to bootloader config is configured"
   file_mug_chk() 
   { 
      l_out="" l_out2="" 
      [[ "$(dirname "$l_file")" =~ ^\/boot\/efi\/EFI ]] && l_pmask="0077" || l_pmask="0177" 
      l_maxperm="$( printf '%o' $(( 0777 & ~$l_pmask )) )" 
      if [ $(( $l_mode & $l_pmask )) -gt 0 ]; then 
         l_out2="$l_out2\n   - Is mode \"$l_mode\" and should be mode: \"$l_maxperm\" or more restrictive" 
      else 
         l_out="$l_out\n   - Is correctly mode: \"$l_mode\" which is mode: \"$l_maxperm\" or more restrictive" 
      fi 
      if [ "$l_user" = "root" ]; then 
         l_out="$l_out\n   - Is correctly owned by user: \"$l_user\"" 
      else 
         l_out2="$l_out2\n   - Is owned by user: \"$l_user\" and should be owned by user: \"root\"" 
      fi 
      if [ "$l_group" = "root" ]; then 
         l_out="$l_out\n   - Is correctly group-owned by group: \"$l_user\"" 
      else 
         l_out2="$l_out2\n   - Is group-owned by group: \"$l_user\" and should be group-owned by group: \"root\"" 
      fi 
      [ -n "$l_out" ] && l_output="$l_output\n  - File: \"$l_file\"$l_out\n" 
      [ -n "$l_out2" ] && l_output2="$l_output2\n  - File: \"$l_file\"$l_out2\n" 
   } 
   while IFS= read -r -d $'\0' l_gfile; do 
      while read -r l_file l_mode l_user l_group; do 
         file_mug_chk 
      done <<< "$(stat -Lc '%n %#a %U %G' "$l_gfile")" 
   done < <(find /boot -type f \( -name 'grub*' -o -name 'user.cfg' \) -print0) 
   if [ -z "$l_output2" ]; then 
      echo -e "\n- Audit Result:\n  *** PASS ***\n- * Correctly set * :\n$l_output\n"
      log_pass "bootloader config access set correctly"
   else 
      echo -e "\n- Audit Result:\n  ** FAIL **\n - * Reasons for audit failure * :\n$l_output2\n" 
      [ -n "$l_output" ] && echo -e " - * Correctly set * :\n$l_output\n"
      log_fail "bootloader config access IS NOT set correctly"
   fi 
}

check_address_space_layout(){ 
   l_output="" l_output2="" 
   a_parlist=("kernel.randomize_va_space=2") 
   l_ufwscf="$([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/ {print $2}' /etc/default/ufw)"
   print_header "1.5.1 - Ensure address space layout randomization is enabled"
   kernel_parameter_chk() 
   {   
      l_krp="$(sysctl "$l_kpname" | awk -F= '{print $2}' | xargs)" # Check running configuration 
      if [ "$l_krp" = "$l_kpvalue" ]; then 
         l_output="$l_output\n - \"$l_kpname\" is correctly set to \"$l_krp\" in the running configuration" 
      else 
         l_output2="$l_output2\n - \"$l_kpname\" is incorrectly set to \"$l_krp\" in the running configuration and should have a value of: \"$l_kpvalue\"" 
      fi 
      unset A_out; declare -A A_out # Check durable setting (files) 
      while read -r l_out; do 
         if [ -n "$l_out" ]; then 
            if [[ $l_out =~ ^\s*# ]]; then 
               l_file="${l_out//# /}" 
            else 
               l_kpar="$(awk -F= '{print $1}' <<< "$l_out" | xargs)" 
               [ "$l_kpar" = "$l_kpname" ] && A_out+=(["$l_kpar"]="$l_file") 
            fi 
         fi 
      done < <(/usr/lib/systemd/systemd-sysctl --cat-config | grep -Po '^\h*([^#\n\r]+|#\h*\/[^#\n\r\h]+\.conf\b)') 
      if [ -n "$l_ufwscf" ]; then # Account for systems with UFW (Not covered by systemd-sysctl --cat-config) 
         l_kpar="$(grep -Po "^\h*$l_kpname\b" "$l_ufwscf" | xargs)" 
         l_kpar="${l_kpar//\//.}" 
         [ "$l_kpar" = "$l_kpname" ] && A_out+=(["$l_kpar"]="$l_ufwscf") 
      fi 
      if (( ${#A_out[@]} > 0 )); then # Assess output from files and generate output 
         while IFS="=" read -r l_fkpname l_fkpvalue; do 
            l_fkpname="${l_fkpname// /}"; l_fkpvalue="${l_fkpvalue// /}" 
            if [ "$l_fkpvalue" = "$l_kpvalue" ]; then 
               l_output="$l_output\n - \"$l_kpname\" is correctly set to \"$l_krp\" in \"$(printf '%s' "${A_out[@]}")\"\n" 
            else 
               l_output2="$l_output2\n - \"$l_kpname\" is incorrectly set to \"$l_fkpvalue\" in \"$(printf '%s' "${A_out[@]}")\" and should have a value of: \"$l_kpvalue\"\n" 
            fi 
         done < <(grep -Po -- "^\h*$l_kpname\h*=\h*\H+" "${A_out[@]}") 
      else 
         l_output2="$l_output2\n - \"$l_kpname\" is not set in an included file\n   ** Note: \"$l_kpname\" May be set in a file that's ignored by load procedure **\n" 
      fi 
   } 
   while IFS="=" read -r l_kpname l_kpvalue; do # Assess and check parameters 
      l_kpname="${l_kpname// /}"; l_kpvalue="${l_kpvalue// /}" 
      if ! grep -Pqs '^\h*0\b' /sys/module/ipv6/parameters/disable && grep -q '^net.ipv6.' <<< "$l_kpname"; then 
         l_output="$l_output\n - IPv6 is disabled on the system, \"$l_kpname\" is not applicable" 
      else 
         kernel_parameter_chk 
      fi 
   done < <(printf '%s\n' "${a_parlist[@]}") 
   if [ -z "$l_output2" ]; then # Provide output from checks 
      echo -e "\n- Audit Result:\n  ** PASS **\n$l_output\n" 
      log_pass "ASLR is set correctly"
   else 
      echo -e "\n- Audit Result:\n  ** FAIL **\n - Reason(s) for audit failure:\n$l_output2\n" 
      [ -n "$l_output" ] && echo -e "\n- Correctly set:\n$l_output\n"
      log_fail "ASLR IS NOT set correctly"
   fi 
}

check_ptrace_scope(){ 
   l_output="" l_output2="" 
   a_parlist=("kernel.yama.ptrace_scope=1") 
   l_ufwscf="$([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/ {print $2}' /etc/default/ufw)"
   print_header "1.5.2 - Ensure ptrace_scope is restricted"
   kernel_parameter_chk() 
   {   
      l_krp="$(sysctl "$l_kpname" | awk -F= '{print $2}' | xargs)" # Check running configuration 
      if [ "$l_krp" = "$l_kpvalue" ]; then 
         l_output="$l_output\n - \"$l_kpname\" is correctly set to \"$l_krp\" in the running configuration" 
      else 
         l_output2="$l_output2\n - \"$l_kpname\" is incorrectly set to \"$l_krp\" in the running configuration and should have a value of: \"$l_kpvalue\"" 
      fi 
      unset A_out; declare -A A_out # Check durable setting (files) 
      while read -r l_out; do 
         if [ -n "$l_out" ]; then 
            if [[ $l_out =~ ^\s*# ]]; then 
               l_file="${l_out//# /}" 
            else 
               l_kpar="$(awk -F= '{print $1}' <<< "$l_out" | xargs)" 
               [ "$l_kpar" = "$l_kpname" ] && A_out+=(["$l_kpar"]="$l_file") 
            fi 
         fi 
      done < <(/usr/lib/systemd/systemd-sysctl --cat-config | grep -Po '^\h*([^#\n\r]+|#\h*\/[^#\n\r\h]+\.conf\b)') 
      if [ -n "$l_ufwscf" ]; then # Account for systems with UFW (Not covered by systemd-sysctl --cat-config) 
         l_kpar="$(grep -Po "^\h*$l_kpname\b" "$l_ufwscf" | xargs)" 
         l_kpar="${l_kpar//\//.}" 
         [ "$l_kpar" = "$l_kpname" ] && A_out+=(["$l_kpar"]="$l_ufwscf") 
      fi 
      if (( ${#A_out[@]} > 0 )); then # Assess output from files and generate output 
         while IFS="=" read -r l_fkpname l_fkpvalue; do 
            l_fkpname="${l_fkpname// /}"; l_fkpvalue="${l_fkpvalue// /}" 
            if [ "$l_fkpvalue" = "$l_kpvalue" ]; then 
               l_output="$l_output\n - \"$l_kpname\" is correctly set to \"$l_krp\" in \"$(printf '%s' "${A_out[@]}")\"\n" 
            else 
               l_output2="$l_output2\n - \"$l_kpname\" is incorrectly set to \"$l_fkpvalue\" in \"$(printf '%s' "${A_out[@]}")\" and should have a value of: \"$l_kpvalue\"\n" 
            fi 
         done < <(grep -Po -- "^\h*$l_kpname\h*=\h*\H+" "${A_out[@]}") 
      else 
         l_output2="$l_output2\n - \"$l_kpname\" is not set in an included file\n   ** Note: \"$l_kpname\" May be set in a file that's ignored by load procedure **\n" 
      fi 
   } 
   while IFS="=" read -r l_kpname l_kpvalue; do # Assess and check parameters 
      l_kpname="${l_kpname// /}"; l_kpvalue="${l_kpvalue// /}" 
      if ! grep -Pqs '^\h*0\b' /sys/module/ipv6/parameters/disable && grep -q '^net.ipv6.' <<< "$l_kpname"; then 
         l_output="$l_output\n - IPv6 is disabled on the system, \"$l_kpname\" is not applicable" 
      else 
         kernel_parameter_chk 
      fi 
   done < <(printf '%s\n' "${a_parlist[@]}") 
   if [ -z "$l_output2" ]; then # Provide output from checks 
      echo -e "\n- Audit Result:\n  ** PASS **\n$l_output\n"
      log_pass "ptrace_scope is set correctly" 
   else 
      echo -e "\n- Audit Result:\n  ** FAIL **\n - Reason(s) for audit failure:\n$l_output2\n" 
      [ -n "$l_output" ] && echo -e "\n- Correctly set:\n$l_output\n"
      log_fail "ptrace_scope IS NOT set correctly"
   fi 
}

check_core_dump_tracebacks(){ 
   l_output="" l_output2="" 
   a_parlist=("ProcessSizeMax=0") 
   l_systemd_config_file="/etc/systemd/coredump.conf" # Main systemd configuration file
   print_header "1.5.3 - Ensure core dump backtraces are disabled"
   config_file_parameter_chk() 
   { 
      unset A_out; declare -A A_out # Check config file(s) setting 
      while read -r l_out; do 
         if [ -n "$l_out" ]; then 
            if [[ $l_out =~ ^\s*# ]]; then 
               l_file="${l_out//# /}" 
            else 
               l_systemd_parameter="$(awk -F= '{print $1}' <<< "$l_out" | xargs)" 
               grep -Piq -- "^\h*$l_systemd_parameter_name\b" <<< "$l_systemd_parameter" && A_out+=(["$l_systemd_parameter"]="$l_file") 
            fi 
         fi 
      done < <(/usr/bin/systemd-analyze cat-config "$l_systemd_config_file" | grep Pio '^\h*([^#\n\r]+|#\h*\/[^#\n\r\h]+\.conf\b)') 
      if (( ${#A_out[@]} > 0 )); then # Assess output from files and generate output 
         while IFS="=" read -r l_systemd_file_parameter_name l_systemd_file_parameter_value; do 
            l_systemd_file_parameter_name="${l_systemd_file_parameter_name// /}" 
            l_systemd_file_parameter_value="${l_systemd_file_parameter_value// /}" 
            if grep -Piq "^\h*$l_systemd_parameter_value\b" <<< "$l_systemd_file_parameter_value"; then 
               l_output="$l_output\n - \"$l_systemd_parameter_name\" is correctly set to \"$l_systemd_file_parameter_value\" in \"$(printf '%s' "${A_out[@]}")\"\n" 
            else 
               l_output2="$l_output2\n - \"$l_systemd_parameter_name\" is incorrectly set to \"$l_systemd_file_parameter_value\" in \"$(printf '%s' "${A_out[@]}")\" and should have a value matching: \"$l_systemd_parameter_value\"\n" 
            fi 
         done < <(grep -Pio -- "^\h*$l_systemd_parameter_name\h*=\h*\H+" "${A_out[@]}") 
      else 
         l_output2="$l_output2\n - \"$l_systemd_parameter_name\" is not set in an included file\n   ** Note: \"$l_systemd_parameter_name\" May be set in a file that's ignored by load procedure **\n" 
      fi 
   } 
   while IFS="=" read -r l_systemd_parameter_name l_systemd_parameter_value; do # Assess and check parameters 
      l_systemd_parameter_name="${l_systemd_parameter_name// /}" 
      l_systemd_parameter_value="${l_systemd_parameter_value// /}" 
      config_file_parameter_chk 
   done < <(printf '%s\n' "${a_parlist[@]}") 
   if [ -z "$l_output2" ]; then # Provide output from checks 
      echo -e "\n- Audit Result:\n  ** PASS **\n$l_output\n"
      log_pass "core dump backtraces is disabled"
   else 
      echo -e "\n- Audit Result:\n  ** FAIL **\n - Reason(s) for audit failure:\n$l_output2" 
      [ -n "$l_output" ] && echo -e "\n- Correctly set:\n$l_output\n"
      log_fail "core dump backtraces IS NOT disabled"
   fi 
}

check_core_dump_storage(){ 
   l_output="" l_output2="" 
   a_parlist=("Storage=none") 
   l_systemd_config_file="/etc/systemd/coredump.conf" # Main systemd configuration file
   print_header "1.5.4 - Ensure core dump storage is disabled"
   config_file_parameter_chk() 
   { 
      unset A_out; declare -A A_out # Check config file(s) setting 
      while read -r l_out; do 
         if [ -n "$l_out" ]; then 
            if [[ $l_out =~ ^\s*# ]]; then 
               l_file="${l_out//# /}" 
            else 
               l_systemd_parameter="$(awk -F= '{print $1}' <<< "$l_out" | xargs)" 
               grep -Piq -- "^\h*$l_systemd_parameter_name\b" <<< "$l_systemd_parameter" && A_out+=(["$l_systemd_parameter"]="$l_file") 
            fi 
         fi 
      done < <(/usr/bin/systemd-analyze cat-config "$l_systemd_config_file" | grep Pio '^\h*([^#\n\r]+|#\h*\/[^#\n\r\h]+\.conf\b)') 
      if (( ${#A_out[@]} > 0 )); then # Assess output from files and generate output 
         while IFS="=" read -r l_systemd_file_parameter_name l_systemd_file_parameter_value; do 
            l_systemd_file_parameter_name="${l_systemd_file_parameter_name// /}" 
            l_systemd_file_parameter_value="${l_systemd_file_parameter_value// /}" 
            if grep -Piq "^\h*$l_systemd_parameter_value\b" <<< "$l_systemd_file_parameter_value"; then 
               l_output="$l_output\n - \"$l_systemd_parameter_name\" is correctly set to \"$l_systemd_file_parameter_value\" in \"$(printf '%s' "${A_out[@]}")\"\n" 
            else 
               l_output2="$l_output2\n - \"$l_systemd_parameter_name\" is incorrectly set to \"$l_systemd_file_parameter_value\" in \"$(printf '%s' "${A_out[@]}")\" and should have a value matching: \"$l_systemd_parameter_value\"\n" 
            fi 
         done < <(grep -Pio -- "^\h*$l_systemd_parameter_name\h*=\h*\H+" "${A_out[@]}") 
      else 
         l_output2="$l_output2\n - \"$l_systemd_parameter_name\" is not set in an included file\n   ** Note: \"$l_systemd_parameter_name\" May be set in a file that's ignored by load procedure **\n" 
      fi 
   } 
   while IFS="=" read -r l_systemd_parameter_name l_systemd_parameter_value; do # Assess and check parameters 
      l_systemd_parameter_name="${l_systemd_parameter_name// /}" 
      l_systemd_parameter_value="${l_systemd_parameter_value// /}" 
      config_file_parameter_chk 
   done < <(printf '%s\n' "${a_parlist[@]}") 
   if [ -z "$l_output2" ]; then # Provide output from checks 
      echo -e "\n- Audit Result:\n  ** PASS **\n$l_output\n"
      log_pass "core dump storage is disabled"
   else 
      echo -e "\n- Audit Result:\n  ** FAIL **\n - Reason(s) for audit failure:\n$l_output2" 
      [ -n "$l_output" ] && echo -e "\n- Correctly set:\n$l_output\n"
      log_fail "core dump storage IS NOT disabled"
   fi 
}

check_crypto_policy_not_legacy() {
   print_header "1.6.1 - Ensure system wide crypto policy is not set to legacy"
    if grep -Pi '^\h*LEGACY\b' /etc/crypto-policies/config > /dev/null 2>&1; then
        log_fail "LEGACY crypto policy is configured (non-compliant)"
    else
        log_pass "LEGACY crypto policy is NOT configured (compliant)"
    fi
}

check_sshd_crypto_policy_defined() {
   print_header "1.6.2 - Ensure system wide crypto policy is not set in sshd configuration"
    if grep -Pi '^\h*CRYPTO_POLICY\h*=' /etc/sysconfig/sshd > /dev/null 2>&1; then
        log_pass "CRYPTO_POLICY is defined in /etc/sysconfig/sshd"
    else
        log_fail "CRYPTO_POLICY IS NOT defined in /etc/sysconfig/sshd"
    fi
}

check_sha1_not_in_crypto_policy() {
    print_header "1.6.3 - Ensure system wide crypto policy disables sha1 hash and signature support"
    if awk -F= '($1~/(hash|sign)/ && $2~/SHA1/ && $2!~/^\s*\s*([^#\n\r]+)?SHA1/)' /etc/crypto-policies/state/CURRENT.pol | grep -q .; then
        log_fail "SHA1 is used in crypto policy (non-compliant)"
    else
        log_pass "SHA1 is not used in crypto policy (compliant)"
    fi
}

check_mac_truncated_64_not_used() {
    print_header "1.6.4 - Ensure system wide crypto policy disables macs less than 128 bits"
    local policy_file="/etc/crypto-policies/state/CURRENT.pol"

    if grep -Pi -- '^\h*mac\h*=\h*([^#\n\r]+)?-64\b' "$policy_file" > /dev/null 2>&1; then
        log_fail "Truncated 64-bit MACs ARE used in crypto policy (non-compliant)"
    else
        log_pass "No truncated 64-bit MACs found in crypto policy (compliant)"
    fi
}

check_cbc_policy(){
   print_header "1.6.5 - Ensure system wide crypto policy disables cbc for ssh"
   l_output="" l_output2="" 
   if grep -Piq -- '^\h*cipher\h*=\h*([^#\n\r]+)?-CBC\b' /etc/crypto-policies/state/CURRENT.pol; then 
      if grep -Piq -- '^\h*cipher@(lib|open)ssh(-server|-client)?\h*=\h*' /etc/crypto-policies/state/CURRENT.pol; then 
         if ! grep -Piq -- '^\h*cipher@(lib|open)ssh(-server|client)?\h*=\h*([^#\n\r]+)?-CBC\b' /etc/crypto-policies/state/CURRENT.pol; then 
            l_output="$l_output\n - Cipher Block Chaining (CBC) is disabled for SSH" 
         else 
            l_output2="$l_output2\n - Cipher Block Chaining (CBC) is enabled for SSH" 
         fi 
      else 
         l_output2="$l_output2\n - Cipher Block Chaining (CBC) is enabled for SSH" 
      fi 
   else 
      l_output=" - Cipher Block Chaining (CBC) is disabled" 
   fi 
   if [ -z "$l_output2" ]; then # Provide output from checks 
      echo -e "\n- Audit Result:\n  ** PASS **\n$l_output\n"
      log_pass "CBC disabled for SSH"
   else 
      echo -e "\n- Audit Result:\n  ** FAIL **\n - Reason(s) for audit failure:\n$l_output2\n" 
      [ -n "$l_output" ] && echo -e "\n- Correctly set:\n$l_output\n"
      log_fail "CBC ENABLED for SSH"
   fi 
}

check_motd(){ 
   print_header "1.7.1 - Ensure message of the day is configured properly"
   l_output="" l_output2="" 
   a_files=() 
   for l_file in /etc/motd{,.d/*}; do 
      if grep -Psqi -- "(\\\v|\\\r|\\\m|\\\s|\b$(grep ^ID= /etc/os-release | cut -d= -f2 | sed -e 's/"//g')\b)" "$l_file"; then 
         l_output2="$l_output2\n - File: \"$l_file\" includes system information" 
      else 
         a_files+=("$l_file") 
      fi 
   done 
   if [ "${#a_files[@]}" -gt 0 ]; then 
      echo -e "\n-  ** Please review the following files and verify their contents follow local site policy **\n" 
      printf '%s\n' "${a_files[@]}" 
   elif [ -z "$l_output2" ]; then 
      echo -e "- ** No MOTD files with any size were found. Please verify this conforms to local site policy ** -" 
   fi 
   if [ -z "$l_output2" ]; then 
      l_output=" - No MOTD files include system information" 
      echo -e "\n- Audit Result:\n  ** PASS **\n$l_output\n"
      log_pass "message of the day properly configured"
   else 
      echo -e "\n- Audit Result:\n  ** FAIL **\n - Reason(s) for audit failure:\n$l_output2\n"
      log_fail "message of the day IMPROPERLY configured"
   fi 
}

check_banner_for_os_info() {
    local target_file="$1"
    local os_id
    print_header "1.7.X - Ensure login warning banner is configured properly"
    os_id=$(grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"')

    if grep -E -i "(\\\v|\\\r|\\\m|\\\s|\\b$os_id\\b)" "$target_file" > /dev/null 2>&1; then
        log_fail "$target_file CONTAINS system information (escape sequences or OS ID: $os_id)"
    else
        log_pass "$target_file does not contain system information (compliant)"
    fi
}

check_banner_file_permissions() {
    local file="$1"
    print_header "1.7.X - Ensure access to $file is configured"

    if [ -e "$file" ]; then
        local mode uid user gid group
        read -r _ mode uid user gid group <<< "$(stat -Lc '%n %#a %u %U %g %G' "$file")"

        local fail=0

        # Permissions must be 644 (octal) or more restrictive
        if [ "$((mode))" -gt 644 ]; then
            log_fail "$file permissions are too permissive: $mode"
            fail=1
        fi

        # Must be owned by root
        if [ "$user" != "root" ]; then
            log_fail "$file is NOT owned by root (owner is $user)"
            fail=1
        fi

        if [ "$group" != "root" ]; then
            log_fail "$file is NOT group-owned by root (group is $group)"
            fail=1
        fi

        if [ "$fail" -eq 0 ]; then
            log_pass "$file has compliant permissions and ownership"
        fi
    else
        log_fail "$file does NOT exist (non-compliant)"
    fi
}

check_gdm_banner(){ 
   print_header "1.8.2 - Ensure GDM login banner is configured"
   l_pkgoutput=""
   # Check if GNOME Desktop Manager is installed.  If package isn't installed, recommendation is Not Applicable\n 
   # determine system's package manager 
   if command -v dpkg-query > /dev/null 2>&1; then 
      l_pq="dpkg-query -W" 
   elif command -v rpm > /dev/null 2>&1; then 
      l_pq="rpm -q" 
   fi 
   l_pcl="gdm gdm3" # Space separated list of packages to check 
   for l_pn in $l_pcl; do 
      $l_pq "$l_pn" > /dev/null 2>&1 && l_pkgoutput="$l_pkgoutput\n - Package: \"$l_pn\" exists on the system\n - checking configuration" 
   done 
   if [ -n "$l_pkgoutput" ]; then 
      l_output="" l_output2="" 
      echo -e "$l_pkgoutput" 
      # Look for existing settings and set variables if they exist 
      l_gdmfile="$(grep -Prils '^\h*banner-message-enable\b' /etc/dconf/db/*.d)" 
      if [ -n "$l_gdmfile" ]; then 
         # Set profile name based on dconf db directory ({PROFILE_NAME}.d) 
         l_gdmprofile="$(awk -F\/ '{split($(NF-1),a,".");print a[1]}' <<< "$l_gdmfile")" 
         # Check if banner message is enabled 
         if grep -Pisq '^\h*banner-message-enable=true\b' "$l_gdmfile"; then 
            l_output="$l_output\n - The \"banner-message-enable\" option is enabled in \"$l_gdmfile\"" 
         else 
            l_output2="$l_output2\n - The \"banner-message-enable\" option is not enabled" 
         fi 
         l_lsbt="$(grep -Pios '^\h*banner-message-text=.*$' "$l_gdmfile")" 
         if [ -n "$l_lsbt" ]; then 
            l_output="$l_output\n - The \"banner-message-text\" option is set in \"$l_gdmfile\"\n  - banner-message-text is set to:\n  - \"$l_lsbt\"" 
         else 
            l_output2="$l_output2\n - The \"banner-message-text\" option is not set" 
         fi 
         if grep -Pq "^\h*system-db:$l_gdmprofile" /etc/dconf/profile/"$l_gdmprofile"; then 
            l_output="$l_output\n - The \"$l_gdmprofile\" profile exists" 
         else 
            l_output2="$l_output2\n - The \"$l_gdmprofile\" profile doesn't exist" 
         fi 
         if [ -f "/etc/dconf/db/$l_gdmprofile" ]; then 
            l_output="$l_output\n - The \"$l_gdmprofile\" profile exists in the dconf database" 
         else 
            l_output2="$l_output2\n - The \"$l_gdmprofile\" profile doesn't exist in the dconf database" 
         fi 
      else 
         l_output2="$l_output2\n - The \"banner-message-enable\" option isn't configured" 
      fi 
   else 
      echo -e "\n\n - GNOME Desktop Manager isn't installed\n - Recommendation is Not Applicable\n- Audit result:\n  *** PASS ***\n" 
   fi 
   # Report results. If no failures output in l_output2, we pass 
   if [ -z "$l_output2" ]; then 
      echo -e "\n- Audit Result:\n  ** PASS **\n$l_output\n"
      log_pass "gdm login banner configured"
   else 
      echo -e "\n- Audit Result:\n  ** FAIL **\n - Reason(s) for audit failure:\n$l_output2\n" 
      [ -n "$l_output" ] && echo -e "\n- Correctly set:\n$l_output\n"
      log_fail "gdm loging banner NOT configured"
   fi 
}

ensure_gdm_disable_user_list_enabled(){
   print_header "1.8.3 - Ensure GDM disable-user-list option is enabled"
   l_pkgoutput=""
   # Check if GNOME Desktop Manager is installed.  If package isn't installed, recommendation is Not Applicable\n 
   # determine system's package manager 
   if command -v dpkg-query > /dev/null 2>&1; then 
      l_pq="dpkg-query -W" 
   elif command -v rpm > /dev/null 2>&1; then 
      l_pq="rpm -q" 
   fi 
   l_pcl="gdm gdm3" # Space separated list of packages to check 
   for l_pn in $l_pcl; do 
      $l_pq "$l_pn" > /dev/null 2>&1 && l_pkgoutput="$l_pkgoutput\n - Package: \"$l_pn\" exists on the system\n - checking configuration" 
   done 
   if [ -n "$l_pkgoutput" ]; then 
      output="" output2="" 
      l_gdmfile="$(grep -Pril '^\h*disable-user-list\h*=\h*true\b' /etc/dconf/db)" 
      if [ -n "$l_gdmfile" ]; then 
         output="$output\n - The \"disable-user-list\" option is enabled in \"$l_gdmfile\"" 
         l_gdmprofile="$(awk -F\/ '{split($(NF-1),a,".");print a[1]}' <<< "$l_gdmfile")" 
         if grep -Pq "^\h*system-db:$l_gdmprofile" /etc/dconf/profile/"$l_gdmprofile"; then 
            output="$output\n - The \"$l_gdmprofile\" exists" 
         else 
            output2="$output2\n - The \"$l_gdmprofile\" doesn't exist" 
         fi 
         if [ -f "/etc/dconf/db/$l_gdmprofile" ]; then 
            output="$output\n - The \"$l_gdmprofile\" profile exists in the dconf database" 
         else 
            output2="$output2\n - The \"$l_gdmprofile\" profile doesn't exist in the dconf database" 
         fi 
      else 
         output2="$output2\n - The \"disable-user-list\" option is not enabled" 
      fi 
      if [ -z "$output2" ]; then 
         echo -e "$l_pkgoutput\n- Audit result:\n   *** PASS: ***\n$output\n"
         log_pass "gdm disable-user-list option is enabled"
      else 
         echo -e "$l_pkgoutput\n- Audit Result:\n   *** FAIL: ***\n$output2\n" 
         [ -n "$output" ] && echo -e "$output\n"
         log_fail "gdm disable-user-list option is NOT enabled"
      fi 
   else 
      echo -e "\n\n - GNOME Desktop Manager isn't installed\n - Recommendation is Not Applicable\n- Audit result:\n  *** PASS ***\n"
      log_pass "gdm is not installed"
   fi 
}

check_gdm_screen_locks(){
   print_header "1.8.4 - Ensure GDM screen locks when the user is idle" 
   l_pkgoutput=""
   # Check if GNOME Desktop Manager is installed.  If package isn't installed, recommendation is Not Applicable\n 
   # determine system's package manager 
   if command -v dpkg-query > /dev/null 2>&1; then 
      l_pq="dpkg-query -W" 
   elif command -v rpm > /dev/null 2>&1; then 
      l_pq="rpm -q" 
   fi 
   # Check if GDM is installed 
   l_pcl="gdm gdm3" # Space separated list of packages to check 
   for l_pn in $l_pcl; do 
      $l_pq "$l_pn" > /dev/null 2>&1 && l_pkgoutput="$l_pkgoutput\n - Package: \"$l_pn\" exists on the system\n - checking configuration" 
   done 
   # Check configuration (If applicable) 
   if [ -n "$l_pkgoutput" ]; then 
      l_output="" l_output2="" 
      l_idmv="900" # Set for max value for idle-delay in seconds 
      l_ldmv="5" # Set for max value for lock-delay in seconds 
      # Look for idle-delay to determine profile in use, needed for remaining tests 
      l_kfile="$(grep -Psril '^\h*idle-delay\h*=\h*uint32\h+\d+\b' /etc/dconf/db/*/)" # Determine file containing idle-delay key 
      if [ -n "$l_kfile" ]; then 
         # set profile name (This is the name of a dconf database) 
         l_profile="$(awk -F'/' '{split($(NF-1),a,".");print a[1]}' <<< "$l_kfile")" #Set the key profile name 
         l_pdbdir="/etc/dconf/db/$l_profile.d" # Set the key file dconf db directory 
         # Confirm that idle-delay exists, includes unit32, and value is between 1 and max value for idle-delay 
         l_idv="$(awk -F 'uint32' '/idle-delay/{print $2}' "$l_kfile" | xargs)" 
         if [ -n "$l_idv" ]; then 
            [ "$l_idv" -gt "0" -a "$l_idv" -le "$l_idmv" ] && l_output="$l_output\n - The \"idle-delay\" option is set to \"$l_idv\" seconds in \"$l_kfile\"" 
            [ "$l_idv" = "0" ] && l_output2="$l_output2\n - The \"idle-delay\" option is set to \"$l_idv\" (disabled) in \"$l_kfile\"" 
            [ "$l_idv" -gt "$l_idmv" ] && l_output2="$l_output2\n - The \"idle-delay\" option is set to \"$l_idv\" seconds (greater than $l_idmv) in \"$l_kfile\"" 
         else 
            l_output2="$l_output2\n - The \"idle-delay\" option is not set in \"$l_kfile\"" 
         fi 
         # Confirm that lock-delay exists, includes unit32, and value is between 0 and max value for lock-delay 
         l_ldv="$(awk -F 'uint32' '/lock-delay/{print $2}' "$l_kfile" | xargs)" 
         if [ -n "$l_ldv" ]; then 
            [ "$l_ldv" -ge "0" -a "$l_ldv" -le "$l_ldmv" ] && l_output="$l_output\n - The \"lock-delay\" option is set to \"$l_ldv\" seconds in \"$l_kfile\"" 
            [ "$l_ldv" -gt "$l_ldmv" ] && l_output2="$l_output2\n - The \"lock-delay\" option is set to \"$l_ldv\" seconds (greater than $l_ldmv) in \"$l_kfile\"" 
         else 
            l_output2="$l_output2\n - The \"lock-delay\" option is not set in \"$l_kfile\"" 
         fi 
         # Confirm that dconf profile exists 
         if grep -Psq "^\h*system-db:$l_profile" /etc/dconf/profile/*; then 
            l_output="$l_output\n - The \"$l_profile\" profile exists" 
         else 
            l_output2="$l_output2\n - The \"$l_profile\" doesn't exist" 
         fi 
         # Confirm that dconf profile database file exists 
         if [ -f "/etc/dconf/db/$l_profile" ]; then 
            l_output="$l_output\n - The \"$l_profile\" profile exists in the dconf database" 
         else 
            l_output2="$l_output2\n - The \"$l_profile\" profile doesn't exist in the dconf database" 
         fi 
      else 
         l_output2="$l_output2\n - The \"idle-delay\" option doesn't exist, remaining tests skipped" 
      fi 
   else 
      l_output="$l_output\n - GNOME Desktop Manager package is not installed on the system\n  - Recommendation is not applicable" 
   fi 
   # Report results. If no failures output in l_output2, we pass 
   [ -n "$l_pkgoutput" ] && echo -e "\n$l_pkgoutput" 
   if [ -z "$l_output2" ]; then 
      echo -e "\n- Audit Result:\n  ** PASS **\n$l_output\n"
      log_pass "gdm screen locks when idle"
   else 
      echo -e "\n- Audit Result:\n  ** FAIL **\n - Reason(s) for audit failure:\n$l_output2\n" 
      [ -n "$l_output" ] && echo -e "\n- Correctly set:\n$l_output\n"
      log_fail "gdm screen does NOT lock when idle"
   fi 
}

check_gdm_screen_locks_permission(){ 
   print_header "1.8.5 - Ensure GDM screen locks cannot be overridden"  
   l_pkgoutput=""
   # Check if GNOME Desktop Manager is installed.  If package isn't installed, recommendation is Not Applicable\n 
   # determine system's package manager 
   if command -v dpkg-query > /dev/null 2>&1; then 
      l_pq="dpkg-query -W" 
   elif command -v rpm > /dev/null 2>&1; then 
      l_pq="rpm -q" 
   fi 
   # Check if GDM is installed 
   l_pcl="gdm gdm3" # Space separated list of packages to check 
   for l_pn in $l_pcl; do 
      $l_pq "$l_pn" > /dev/null 2>&1 && l_pkgoutput="$l_pkgoutput\n - Package: \"$l_pn\" exists on the system\n - checking configuration" 
   done 
   # Check configuration (If applicable) 
   if [ -n "$l_pkgoutput" ]; then 
      l_output="" l_output2="" 
      # Look for idle-delay to determine profile in use, needed for remaining tests 
      l_kfd="/etc/dconf/db/$(grep -Psril '^\h*idle-delay\h*=\h*uint32\h+\d+\b' /etc/dconf/db/*/ | awk -F'/' '{split($(NF-1),a,".");print a[1]}').d" #set directory of key file to be locked 
      l_kfd2="/etc/dconf/db/$(grep -Psril '^\h*lock-delay\h*=\h*uint32\h+\d+\b' /etc/dconf/db/*/ | awk -F'/' '{split($(NF-1),a,".");print a[1]}').d" #set directory of key file to be locked 
      if [ -d "$l_kfd" ]; then # If key file directory doesn't exist, options can't be locked 
         if grep -Prilq '\/org\/gnome\/desktop\/session\/idle-delay\b' "$l_kfd"; then 
            l_output="$l_output\n - \"idle-delay\" is locked in \"$(grep -Pril '\/org\/gnome\/desktop\/session\/idle-delay\b' "$l_kfd")\"" 
         else 
            l_output2="$l_output2\n - \"idle-delay\" is not locked" 
         fi 
      else 
         l_output2="$l_output2\n - \"idle-delay\" is not set so it can not be locked" 
      fi 
      if [ -d "$l_kfd2" ]; then # If key file directory doesn't exist, options can't be locked 
         if grep -Prilq '\/org\/gnome\/desktop\/screensaver\/lock-delay\b' "$l_kfd2"; then 
            l_output="$l_output\n - \"lock-delay\" is locked in \"$(grep -Pril '\/org\/gnome\/desktop\/screensaver\/lock-delay\b' "$l_kfd2")\"" 
         else 
            l_output2="$l_output2\n - \"lock-delay\" is not locked" 
         fi 
      else 
         l_output2="$l_output2\n - \"lock-delay\" is not set so it can not be locked" 
      fi 
   else 
      l_output="$l_output\n - GNOME Desktop Manager package is not installed on the system\n  - Recommendation is not applicable" 
   fi 
   # Report results. If no failures output in l_output2, we pass  [ -n "$l_pkgoutput" ] && echo -e "\n$l_pkgoutput" 
   if [ -z "$l_output2" ]; then 
      echo -e "\n- Audit Result:\n  ** PASS **\n$l_output\n"
      log_pass "gdm screen lock cannot be overwritten"
   else 
      echo -e "\n- Audit Result:\n  ** FAIL **\n - Reason(s) for audit failure:\n$l_output2\n" 
      [ -n "$l_output" ] && echo -e "\n- Correctly set:\n$l_output\n"
      log_fail "gdm screen lock CAN be overwritten"
   fi 
}

check_gdm_automatic_mounting(){
   print_header "1.8.6 - Ensure GDM automatic mounting of removable media is disabled" 
   l_pkgoutput="" l_output="" l_output2="" 
   # Check if GNOME Desktop Manager is installed.  If package isn't installed, recommendation is Not Applicable\n 
   # determine system's package manager 
   if command -v dpkg-query > /dev/null 2>&1; then 
      l_pq="dpkg-query -W" 
   elif command -v rpm > /dev/null 2>&1; then 
      l_pq="rpm -q" 
   fi 
   # Check if GDM is installed 
   l_pcl="gdm gdm3" # Space separated list of packages to check 
   for l_pn in $l_pcl; do 
      $l_pq "$l_pn" > /dev/null 2>&1 && l_pkgoutput="$l_pkgoutput\n - Package: \"$l_pn\" exists on the system\n - checking configuration" 
   done 
   # Check configuration (If applicable) 
   if [ -n "$l_pkgoutput" ]; then 
      echo -e "$l_pkgoutput" 
      # Look for existing settings and set variables if they exist 
      l_kfile="$(grep -Prils -- '^\h*automount\b' /etc/dconf/db/*.d)" 
      l_kfile2="$(grep -Prils -- '^\h*automount-open\b' /etc/dconf/db/*.d)" 
      # Set profile name based on dconf db directory ({PROFILE_NAME}.d) 
      if [ -f "$l_kfile" ]; then 
         l_gpname="$(awk -F\/ '{split($(NF-1),a,".");print a[1]}' <<< "$l_kfile")" 
      elif [ -f "$l_kfile2" ]; then 
         l_gpname="$(awk -F\/ '{split($(NF-1),a,".");print a[1]}' <<< "$l_kfile2")" 
      fi 
      # If the profile name exist, continue checks 
      if [ -n "$l_gpname" ]; then 
         l_gpdir="/etc/dconf/db/$l_gpname.d" 
         # Check if profile file exists 
         if grep -Pq -- "^\h*system-db:$l_gpname\b" /etc/dconf/profile/*; then 
            l_output="$l_output\n - dconf database profile file \"$(grep -Pl -- "^\h*system-db:$l_gpname\b" /etc/dconf/profile/*)\" exists" 
         else 
            l_output2="$l_output2\n - dconf database profile isn't set" 
         fi 
         # Check if the dconf database file exists 
         if [ -f "/etc/dconf/db/$l_gpname" ]; then 
            l_output="$l_output\n - The dconf database \"$l_gpname\" exists" 
         else 
            l_output2="$l_output2\n - The dconf database \"$l_gpname\" doesn't exist" 
         fi 
         # check if the dconf database directory exists 
         if [ -d "$l_gpdir" ]; then 
            l_output="$l_output\n - The dconf directory \"$l_gpdir\" exist" 
         else 
            l_output2="$l_output2\n - The dconf directory \"$l_gpdir\" doesn't exist" 
         fi
         # check automount setting 
         if grep -Pqrs -- '^\h*automount\h*=\h*false\b' "$l_kfile"; then 
            l_output="$l_output\n - \"automount\" is set to false in: \"$l_kfile\"" 
         else 
            l_output2="$l_output2\n - \"automount\" is not set correctly" 
         fi 
         # check automount-open setting 
         if grep -Pqs -- '^\h*automount-open\h*=\h*false\b' "$l_kfile2"; then 
            l_output="$l_output\n - \"automount-open\" is set to false in: \"$l_kfile2\"" 
         else 
            l_output2="$l_output2\n - \"automount-open\" is not set correctly" 
         fi 
      else 
         # Setings don't exist. Nothing further to check 
         l_output2="$l_output2\n - neither \"automount\" or \"automountopen\" is set" 
      fi 
   else 
      l_output="$l_output\n - GNOME Desktop Manager package is not installed on the system\n  - Recommendation is not applicable" 
   fi 
   # Report results. If no failures output in l_output2, we pass 
   if [ -z "$l_output2" ]; then 
      echo -e "\n- Audit Result:\n  ** PASS **\n$l_output\n"
      log_pass "gdm automatic mounting of removable media is disabled" 
   else 
      echo -e "\n- Audit Result:\n  ** FAIL **\n - Reason(s) for audit failure:\n$l_output2\n" 
      [ -n "$l_output" ] && echo -e "\n- Correctly set:\n$l_output\n"
      log_fail "gdm automatic mounting of removable media IS NOT disabled"  
   fi 
}

check_gdm_automatic_mounting_permission(){
   print_header "1.8.7 - Ensure GDM disabling automatic mounting of removable media is not overridden"
   # Check if GNOME Desktop Manager is installed.  If package isn't installed, recommendation is Not Applicable\n 
   # determine system's package manager 
   l_pkgoutput="" 
   if command -v dpkg-query > /dev/null 2>&1; then 
      l_pq="dpkg-query -W" 
   elif command -v rpm > /dev/null 2>&1; then 
      l_pq="rpm -q" 
   fi 
   # Check if GDM is installed 
   l_pcl="gdm gdm3" # Space separated list of packages to check 
   for l_pn in $l_pcl; do 
      $l_pq "$l_pn" > /dev/null 2>&1 && l_pkgoutput="$l_pkgoutput\n - Package: \"$l_pn\" exists on the system\n - checking configuration" 
   done 
   # Check configuration (If applicable) 
   if [ -n "$l_pkgoutput" ]; then 
      l_output="" l_output2="" 
      echo -e "$l_pkgoutput\n" 
      # Look for idle-delay to determine profile in use, needed for remaining tests 
      l_kfd="/etc/dconf/db/$(grep -Psril '^\h*automount\b' /etc/dconf/db/*/ | awk -F'/' '{split($(NF-1),a,".");print a[1]}').d" #set directory of key file to be locked 
      l_kfd2="/etc/dconf/db/$(grep -Psril '^\h*automount-open\b' /etc/dconf/db/*/ | awk -F'/' '{split($(NF-1),a,".");print a[1]}').d" #set directory of key file to be locked 
      if [ -d "$l_kfd" ]; then # If key file directory doesn't exist, options can't be locked 
         if grep -Priq '^\h*\/org/gnome\/desktop\/media-handling\/automount\b' "$l_kfd"; then 
            l_output="$l_output\n - \"automount\" is locked in \"$(grep -Pril '^\h*\/org/gnome\/desktop\/media-handling\/automount\b' "$l_kfd")\"" 
         else 
            l_output2="$l_output2\n - \"automount\" is not locked" 
         fi 
      else 
         l_output2="$l_output2\n - \"automount\" is not set so it can not be locked" 
      fi 
      if [ -d "$l_kfd2" ]; then # If key file directory doesn't exist, options can't be locked 
         if grep -Priq '^\h*\/org/gnome\/desktop\/media-handling\/automount-open\b' "$l_kfd2"; then 
            l_output="$l_output\n - \"lautomount-open\" is locked in \"$(grep -Pril '^\h*\/org/gnome\/desktop\/media-handling\/automount-open\b' "$l_kfd2")\"" 
         else 
            l_output2="$l_output2\n - \"automount-open\" is not locked" 
         fi 
      else 
         l_output2="$l_output2\n - \"automount-open\" is not set so it can not be locked" 
      fi 
   else 
      l_output="$l_output\n - GNOME Desktop Manager package is not installed on the system\n  - Recommendation is not applicable" 
   fi 
   # Report results. If no failures output in l_output2, we pass 
   if [ -z "$l_output2" ]; then 
      echo -e "\n- Audit Result:\n  ** PASS **\n$l_output\n"
      log_pass "gdm disabling automatic premession is not overridden" 
   else 
      echo -e "\n- Audit Result:\n  ** FAIL **\n - Reason(s) for audit failure:\n$l_output2\n" 
      [ -n "$l_output" ] && echo -e "\n- Correctly set:\n$l_output\n"
      log_fail "gdm disabling automatic premession IS overridden" 
   fi 
}

confirm_gdm_autorun-never(){
   print_header "1.8.8 - Ensure GDM autorun-never is enabled"
   l_pkgoutput="" l_output="" l_output2="" 
   # Check if GNOME Desktop Manager is installed.  If package isn't installed, recommendation is Not Applicable\n 
   # determine system's package manager 
   if command -v dpkg-query > /dev/null 2>&1; then 
      l_pq="dpkg-query -W" 
   elif command -v rpm > /dev/null 2>&1; then 
      l_pq="rpm -q" 
   fi 
   # Check if GDM is installed 
   l_pcl="gdm gdm3" # Space separated list of packages to check 
   for l_pn in $l_pcl; do 
      $l_pq "$l_pn" > /dev/null 2>&1 && l_pkgoutput="$l_pkgoutput\n - Package: \"$l_pn\" exists on the system\n - checking configuration" 
      echo -e "$l_pkgoutput" 
   done 
   # Check configuration (If applicable) 
   if [ -n "$l_pkgoutput" ]; then 
      echo -e "$l_pkgoutput" 
      # Look for existing settings and set variables if they exist 
      l_kfile="$(grep -Prils -- '^\h*autorun-never\b' /etc/dconf/db/*.d)" 
      # Set profile name based on dconf db directory ({PROFILE_NAME}.d) 
      if [ -f "$l_kfile" ]; then 
         l_gpname="$(awk -F\/ '{split($(NF-1),a,".");print a[1]}' <<< "$l_kfile")" 
      fi 
      # If the profile name exist, continue checks 
      if [ -n "$l_gpname" ]; then 
         l_gpdir="/etc/dconf/db/$l_gpname.d" 
         # Check if profile file exists 
         if grep -Pq -- "^\h*system-db:$l_gpname\b" /etc/dconf/profile/*; then 
            l_output="$l_output\n - dconf database profile file \"$(grep -Pl -- "^\h*system-db:$l_gpname\b" /etc/dconf/profile/*)\" exists" 
         else 
            l_output2="$l_output2\n - dconf database profile isn't set" 
         fi 
         # Check if the dconf database file exists 
         if [ -f "/etc/dconf/db/$l_gpname" ]; then 
            l_output="$l_output\n - The dconf database \"$l_gpname\" exists" 
         else 
            l_output2="$l_output2\n - The dconf database \"$l_gpname\" doesn't exist" 
         fi 
         # check if the dconf database directory exists 
         if [ -d "$l_gpdir" ]; then 
            l_output="$l_output\n - The dconf directory \"$l_gpdir\" exitst" 
         else 
            l_output2="$l_output2\n - The dconf directory \"$l_gpdir\" doesn't exist" 
         fi 
         # check autorun-never setting 
         if grep -Pqrs -- '^\h*autorun-never\h*=\h*true\b' "$l_kfile"; then 
            l_output="$l_output\n - \"autorun-never\" is set to true in: \"$l_kfile\""
	 else
            l_output2="$l_output2\n - \"autorun-never\" is not set correctly" 
	  fi 
      else 
	  # Settings don't exist. Nothing further to check 
	  l_output2="$l_output2\n - \"autorun-never\" is not set" 
      fi 
   else
      l_output="$l_output\n - GNOME Desktop Manager package is not installed on the system\n  - Recommendation is not applicable" 
   fi 
   # Report results. If no failures output in l_output2, we pass 
   if [ -z "$l_output2" ]; then 
      echo -e "\n- Audit Result:\n  ** PASS **\n$l_output\n"
      log_pass "gdm autorun-never is enabled" 
   else 
      echo -e "\n- Audit Result:\n  ** FAIL **\n - Reason(s) for audit failure:\n$l_output2\n" 
      [ -n "$l_output" ] && echo -e "\n- Correctly set:\n$l_output\n"
      log_pass "gdm autorun-never is disabled" 
   fi 
}

confirm_gdm_autorun-never_permission(){
   print_header "1.8.9 - Ensure GDM autorun-never is not overridden"
   # Check if GNOME Desktop Manager is installed.  If package isn't installed, recommendation is Not Applicable\n 
   # determine system's package manager 
   l_pkgoutput="" 
   if command -v dpkg-query > /dev/null 2>&1; then 
      l_pq="dpkg-query -W" 
   elif command -v rpm > /dev/null 2>&1; then 
      l_pq="rpm -q" 
   fi 
   # Check if GDM is installed 
   l_pcl="gdm gdm3" # Space separated list of packages to check 
   for l_pn in $l_pcl; do 
      $l_pq "$l_pn" > /dev/null 2>&1 && l_pkgoutput="$l_pkgoutput\n - Package: \"$l_pn\" exists on the system\n - checking configuration" 
   done 
   # Check configuration (If applicable) 
   if [ -n "$l_pkgoutput" ]; then 
      l_output="" l_output2="" 
      echo -e "$l_pkgoutput\n" 
      # Look for idle-delay to determine profile in use, needed for remaining tests 
      l_kfd="/etc/dconf/db/$(grep -Psril '^\h*autorun-never\b' /etc/dconf/db/*/ | awk -F'/' '{split($(NF-1),a,".");print a[1]}').d" #set directory of key file to be locked 
      if [ -d "$l_kfd" ]; then # If key file directory doesn't exist, options can't be locked 
         if grep -Priq '^\h*\/org/gnome\/desktop\/media-handling\/autorunnever\b' "$l_kfd"; then 
            l_output="$l_output\n - \"autorun-never\" is locked in \"$(grep Pril '^\h*\/org/gnome\/desktop\/media-handling\/autorun-never\b' "$l_kfd")\"" 
         else 
            l_output2="$l_output2\n - \"autorun-never\" is not locked" 
         fi 
      else 
         l_output2="$l_output2\n - \"autorun-never\" is not set so it can not be locked" 
      fi 
   else 
      l_output="$l_output\n - GNOME Desktop Manager package is not installed on the system\n  - Recommendation is not applicable" 
   fi 
   # Report results. If no failures output in l_output2, we pass 
   if [ -z "$l_output2" ]; then 
      echo -e "\n- Audit Result:\n  ** PASS **\n$l_output\n"
      log_pass "gdm autorun-never is not overridden"  
   else 
      echo -e "\n- Audit Result:\n  ** FAIL **\n - Reason(s) for audit failure:\n$l_output2\n" 
      [ -n "$l_output" ] && echo -e "\n- Correctly set:\n$l_output\n"
      log_fail "gdm autorun-never IS overridden"  
   fi 
}

check_gdm_enable_not_true() {
    print_header "1.8.10 - Ensure XDMCP is not enabled"
    local gdm_conf="/etc/gdm/custom.conf"

    if grep -Eis '^\s*Enable\s*=\s*true' "$gdm_conf" > /dev/null 2>&1; then
        log_fail "GDM graphical login IS enabled in $gdm_conf (non-compliant)"
    else
        log_pass "GDM graphical login is not enabled in $gdm_conf (compliant)"
    fi
}

check_package_not_installed() {
    local pkg="$1"

    if rpm -q "$pkg" > /dev/null 2>&1; then
        log_fail "$pkg IS installed (non-compliant)"
    else
        log_pass "$pkg is not installed (compliant)"
    fi
}

check_mta_config(){
   print_header "2.1.21 - Ensure mail transfer agents are configured for local-only mode"
   l_output="" l_output2="" 
   a_port_list=("25" "465" "587") 
   if [ "$(postconf -n inet_interfaces)" != "inet_interfaces = all" ]; then 
      for l_port_number in "${a_port_list[@]}"; do 
         if ss -plntu | grep -P -- ':'"$l_port_number"'\b' | grep -Pvq -- '\h+(127\.0\.0\.1|\[?::1\]?):'"$l_port_number"'\b'; then 
               l_output2="$l_output2\n - Port \"$l_port_number\" is listening on a non-loopback network interface" 
         else 
               l_output="$l_output\n - Port \"$l_port_number\" is not listening on a non-loopback network interface" 
         fi 
      done 
   else 
      l_output2="$l_output2\n - Postfix is bound to all interfaces" 
   fi 
   unset a_port_list 
   if [ -z "$l_output2" ]; then 
      echo -e "\n- Audit Result:\n  ** PASS **\n$l_output\n"
      log_pass "mail transfer is configured correctly"
   else 
      echo -e "\n- Audit Result:\n  ** FAIL **\n - Reason(s) for audit failure:\n$l_output2\n" 
      [ -n "$l_output" ] && echo -e "\n- Correctly set:\n$l_output\n"
      log_fail "mail transfer NOT configured correctly"
   fi 
}

check_package_installed() {
    local pkg="$1"

    if rpm -q "$pkg" > /dev/null 2>&1; then
        log_pass "$pkg is installed (compliant)"
    else
        log_fail "$pkg is NOT installed (non-compliant)"
    fi
}

check_chrony_servers_configured() {
    print_header "2.3.2 - Ensure chrony is configured"
    local conf_files=(/etc/chrony.conf)
    [[ -d /etc/chrony.d ]] && conf_files+=($(find /etc/chrony.d -type f))

    local found=0

    for file in "${conf_files[@]}"; do
        if grep -Eiq '^\s*(server|pool)\s+[a-zA-Z0-9]' "$file"; then
            found=1
            break
        fi
    done

    if [ "$found" -eq 1 ]; then
        log_pass "Chrony time sources (server or pool) are configured"
    else
        log_fail "NO chrony time sources (server or pool) found in configuration"
    fi
}

check_chronyd_not_running_as_root() {
    print_header "2.3.3 - Ensure chrony is not run as the root user"
    local conf_file="/etc/sysconfig/chronyd"

    if grep -Psi -- '^\h*OPTIONS=\"?\h*([^#\n\r]+\h+)?-u\h+root\b' "$conf_file" > /dev/null 2>&1; then
        log_fail "chronyd IS configured to run as root in $conf_file (non-compliant)"
    else
        log_pass "chronyd is not configured to run as root (compliant)"
    fi
}

check_cron_service_enabled_and_active() {
    local enabled_status active_status
    print_header "2.4.1.1 - Ensure cron daemon is enabled and active"
    enabled_status=$(systemctl list-unit-files | awk '$1~/^crond?\.service/{print $2}')
    active_status=$(systemctl list-units | awk '$1~/^crond?\.service/{print $3}')

    # Check if enabled
    if [[ "$enabled_status" != "enabled" ]]; then
        if [[ -z "$enabled_status" ]]; then
            log_fail "Cron service NOT found in unit files (non-compliant)"
        else
            log_fail "Cron service IS NOT enabled (status: $enabled_status)"
        fi
    fi

    # Check if active
    if [[ "$active_status" != "running" ]]; then
        if [[ -z "$active_status" ]]; then
            log_fail "Cron service NOT found in active units (non-compliant)"
        else
            log_fail "Cron service IS NOT running (status: $active_status)"
        fi
    fi

    # Pass only if both conditions are met
    if [[ "$enabled_status" == "enabled" && "$active_status" == "running" ]]; then
        log_pass "Cron service is enabled and running (compliant)"
    fi
}

check_crontab_permissions() {
   print_header "2.4.1.2 - Ensure permissions on /etc/crontab are configured"
    if ! rpm -q cronie > /dev/null 2>&1 && ! rpm -q cron > /dev/null 2>&1; then
        log_pass "Cron is not installed; skipping crontab file check"
        return
    fi

    local file="/etc/crontab"

    if [ ! -e "$file" ]; then
        log_fail "$file does NOT exist (non-compliant)"
        return
    fi

    local mode uid user gid group
    read -r _ mode uid user gid group <<< "$(stat -Lc '%n %a %u %U %g %G' "$file")"

    local fail=0

    # Mode check: permissions should be 600 or more restrictive (e.g., not greater than 644)
    if [ "$mode" -gt 644 ]; then
        log_fail "$file permissions ARE too permissive: $mode"
        fail=1
    fi

    # Owner check
    if [ "$user" != "root" ]; then
        log_fail "$file IS owned by $user (expected: root)"
        fail=1
    fi

    # Group check
    if [ "$group" != "root" ]; then
        log_fail "$file IS group-owned by $group (expected: root)"
        fail=1
    fi

    if [ "$fail" -eq 0 ]; then
        log_pass "$file has compliant permissions and ownership"
    fi
}

check_path_permissions() {
    local path="$1"
    local max_perms="$2"
    print_header  "2.4.1.X Ensure permissions on $path are configured"

    if ! rpm -q cronie > /dev/null 2>&1 && ! rpm -q cron > /dev/null 2>&1 && [[ "$path" == /etc/cron* ]]; then
        log_pass "Cron is not installed; skipping $path check"
        return
    fi

    if ! rpm -q at > /dev/null 2>&1 && [[ "$path" == /etc/at.allow ]]; then
        log_pass "at is not installed; skipping $path check"
        return
    fi

    if [ ! -e "$path" ]; then
        log_fail "$path does NOT exist (non-compliant)"
        return
    fi

    local mode user group
    read -r _ mode _ user _ group <<< "$(stat -Lc '%n %a %u %U %g %G' "$path")"

    local fail=0

    if [ "$mode" -gt "$max_perms" ]; then
        log_fail "$path permissions ARE too permissive: $mode (expected $max_perms or more restrictive)"
        fail=1
    fi

    if [ "$user" != "root" ]; then
        log_fail "$path IS owned by $user (expected: root)"
        fail=1
    fi

    if [ "$group" != "root" ]; then
        log_fail "$path IS group-owned by $group (expected: root)"
        fail=1
    fi

    if [ "$fail" -eq 0 ]; then
        log_pass "$path has compliant permissions and ownership"
    fi
}

check_wireless_modules_blocked() {
    local l_output="" l_output2=""
    print_header  "3.1.2 Ensure wireless interfaces are disabled"

    module_chk() {
        local l_mname="$1"
        local fail=0

        # Check how the module would load
        local l_loadable
        l_loadable="$(modprobe -n -v "$l_mname")"

        if grep -Pq -- '^\h*install\s+/bin/(true|false)' <<< "$l_loadable"; then
            l_output+="\n - module \"$l_mname\" is NOT loadable ($l_loadable)"
        else
            l_output2+="\n - module \"$l_mname\" IS loadable ($l_loadable)"
            fail=1
        fi

        # Check if module is currently loaded
        if lsmod | grep -q "^$l_mname"; then
            l_output2+="\n - module \"$l_mname\" IS currently loaded"
            fail=1
        else
            l_output+="\n - module \"$l_mname\" is NOT currently loaded"
        fi

        # Check if module is blacklisted
        if modprobe --showconfig | grep -Pq "^\h*blacklist\s+$l_mname\b"; then
            l_output+="\n - module \"$l_mname\" is deny listed"
        else
            l_output2+="\n - module \"$l_mname\" is NOT deny listed"
            fail=1
        fi

        return $fail
    }

    # Detect wireless modules via sysfs
    if [ -n "$(find /sys/class/net/*/ -type d -name wireless 2>/dev/null)" ]; then
        local modules
        modules=$(for driverdir in $(find /sys/class/net/*/ -type d -name wireless | xargs -n1 dirname); do
            basename "$(readlink -f "$driverdir/device/driver/module")"
        done | sort -u)

        local any_fail=0
        for mod in $modules; do
            if module_chk "$mod"; then
                any_fail=1
            fi
        done
    fi

    # Final audit result
    if [ -z "$modules" ]; then
        log_pass "System has no wireless NICs installed"
    elif [ "$any_fail" -eq 0 ]; then
        log_pass "All wireless modules are blocked or disabled (compliant)"
        echo -e "$l_output"
    else
        log_fail "One or more wireless modules ARE NOT properly disabled"
        echo -e "\n - Reason(s) for audit failure:$l_output2"
        [ -n "$l_output" ] && echo -e "\n - Correctly set:$l_output"
    fi
}

check_kernel_parameters() {
    local header="$1"; shift
    local param_list=("$@")
    local l_output="" l_output2="" l_ipv6_disabled=""
    local l_ufwscf
    l_ufwscf="$([ -f /etc/default/ufw ] && awk -F= '/^\s*IPT_SYSCTL=/ {print $2}' /etc/default/ufw)"

    print_header "$header"

    f_ipv6_chk() {
        l_ipv6_disabled=""
        ! grep -Pqs -- '^\h*0\b' /sys/module/ipv6/parameters/disable && l_ipv6_disabled="yes"
        if sysctl net.ipv6.conf.all.disable_ipv6 | grep -Pqs -- "=\h*1\b" && \
           sysctl net.ipv6.conf.default.disable_ipv6 | grep -Pqs -- "=\h*1\b"; then
            l_ipv6_disabled="yes"
        fi
        [ -z "$l_ipv6_disabled" ] && l_ipv6_disabled="no"
    }

    f_kernel_parameter_chk() {
        local l_kpname="$1"
        local l_kpvalue="$2"
        local l_krp
        l_krp="$(sysctl "$l_kpname" 2>/dev/null | awk -F= '{print $2}' | xargs)"

        if [ "$l_krp" = "$l_kpvalue" ]; then
            l_output+="\n - \"$l_kpname\" is correctly set to \"$l_krp\" in the running configuration"
        else
            l_output2+="\n - \"$l_kpname\" IS incorrectly set to \"$l_krp\" in the running configuration (should be \"$l_kpvalue\")"
        fi

        unset A_out; declare -A A_out
        while read -r l_out; do
            if [ -n "$l_out" ]; then
                if [[ $l_out =~ ^\s*# ]]; then
                    l_file="${l_out//# /}"
                else
                    l_kpar="$(awk -F= '{print $1}' <<< "$l_out" | xargs)"
                    [ "$l_kpar" = "$l_kpname" ] && A_out+=(["$l_kpar"]="$l_file")
                fi
            fi
        done < <(/usr/lib/systemd/systemd-sysctl --cat-config | grep -Po '^\h*([^#\n\r]+|#\h*/[^#\n\r\h]+\.conf\b)')

        if [ -n "$l_ufwscf" ]; then
            l_kpar="$(grep -Po "^\h*$l_kpname\b" "$l_ufwscf" | xargs)"
            l_kpar="${l_kpar//\//.}"
            [ "$l_kpar" = "$l_kpname" ] && A_out+=(["$l_kpar"]="$l_ufwscf")
        fi

        if (( ${#A_out[@]} > 0 )); then
            while IFS="=" read -r l_fkpname l_fkpvalue; do
                l_fkpname="${l_fkpname// /}"; l_fkpvalue="${l_fkpvalue// /}"
                if [ "$l_fkpvalue" = "$l_kpvalue" ]; then
                    l_output+="\n - \"$l_kpname\" is correctly set to \"$l_fkpvalue\" in \"$(printf '%s' "${A_out[@]}")\""
                else
                    l_output2+="\n - \"$l_kpname\" IS incorrectly set to \"$l_fkpvalue\" in \"$(printf '%s' "${A_out[@]}")\" (should be \"$l_kpvalue\")"
                fi
            done < <(grep -Po -- "^\h*$l_kpname\h*=\h*\S+" "${A_out[@]}")
        else
            l_output2+="\n - \"$l_kpname\" is NOT set in any included file"
        fi
    }

    for entry in "${param_list[@]}"; do
        IFS="=" read -r l_kpname l_kpvalue <<< "$entry"
        l_kpname="${l_kpname// /}"
        l_kpvalue="${l_kpvalue// /}"

        if grep -q '^net.ipv6.' <<< "$l_kpname"; then
            [ -z "$l_ipv6_disabled" ] && f_ipv6_chk
            if [ "$l_ipv6_disabled" = "yes" ]; then
                l_output+="\n - IPv6 is disabled, \"$l_kpname\" is not applicable"
                continue
            fi
        fi
        f_kernel_parameter_chk "$l_kpname" "$l_kpvalue"
    done

    if [ -z "$l_output2" ]; then
        echo -e "$l_output\n"
        log_pass "All kernel parameters are correctly configured"
    else
        echo -e "\n - Reason(s) for audit failure:$l_output2"
        [ -n "$l_output" ] && echo -e "\n - Correctly set:$l_output"
        log_fail "One or more kernel parameters ARE NOT correctly configured"
    fi
}

check_firewall_status() {
    print_header "4.1.2 _ Ensure a single firewall configuration utility is in use"

    local l_output="" l_output2=""
    local l_fwd_status="" l_nft_status="" l_fwutil_status=""

    # Check Firewalld status
    if rpm -q firewalld > /dev/null 2>&1; then
        l_fwd_status="$(systemctl is-enabled firewalld 2>/dev/null):$(systemctl is-active firewalld 2>/dev/null)"
    else
        l_fwd_status="notinstalled:notinstalled"
    fi

    # Check nftables status
    if rpm -q nftables > /dev/null 2>&1; then
        l_nft_status="$(systemctl is-enabled nftables 2>/dev/null):$(systemctl is-active nftables 2>/dev/null)"
    else
        l_nft_status="notinstalled:notinstalled"
    fi

    l_fwutil_status="$l_fwd_status:$l_nft_status"

    case "$l_fwutil_status" in
        enabled:active:masked:inactive|enabled:active:disabled:inactive)
            log_pass "FirewallD IS enabled and active, NFTables IS disabled or masked and inactive"
            l_output+="\n - Only configure recommendations in the Firewalld section"
            ;;
        masked:inactive:enabled:active|disabled:inactive:enabled:active)
            log_pass "NFTables IS enabled and active, FirewallD IS disabled or masked and inactive"
            l_output+="\n - Only configure recommendations in the NFTables section"
            ;;
        enabled:active:enabled:active)
            log_fail "Both FirewallD AND NFTables ARE enabled and active — only ONE firewall should be active"
            ;;
        enabled:*:enabled:*)
            log_fail "Both FirewallD AND NFTables ARE enabled — only ONE firewall should be enabled"
            ;;
        *:active:*:active)
            log_fail "Both FirewallD AND NFTables ARE active — only ONE firewall should be active"
            ;;
        notinstalled:notinstalled:notinstalled:notinstalled)
            log_fail "Neither FirewallD NOR NFTables IS installed — install and configure ONE firewall utility"
            ;;
        notinstalled:notinstalled:enabled:active)
            log_pass "NFTables IS enabled and active, FirewallD is not installed"
            l_output+="\n - Only configure recommendations in the NFTables section"
            ;;
        *:*:notinstalled:notinstalled)
            log_fail "NFTables IS NOT installed — install and configure ONE firewall utility"
            ;;
        *)
            log_fail "Unable to determine firewall state — ensure only ONE firewall IS enabled and active"
            ;;
    esac

    # Output final result
    if [ -n "$l_output" ]; then
        echo -e "\n- Audit Detail:$l_output\n"
    fi
}

check_nftables_base_chains() {
    print_header "4.3.1 - Ensure nftables base chains exist"

    local l_output="" l_output2=""
    local required_hooks=("input" "forward" "output")

    # Only run this check if nftables is active
    if ! rpm -q nftables > /dev/null 2>&1 || ! systemctl is-active nftables &>/dev/null; then
        log_pass "NFTables is not active — skipping base chain hook checks"
        return
    fi

    local ruleset
    ruleset="$(nft list ruleset 2>/dev/null)"

    for hook in "${required_hooks[@]}"; do
        if echo "$ruleset" | grep -q "hook $hook"; then
            l_output+="\n - Base chain exists for $hook hook"
        else
            l_output2+="\n - Base chain for $hook hook IS NOT present in nftables ruleset"
        fi
    done

    if [ -z "$l_output2" ]; then
        echo -e "$l_output"
        log_pass "All nftables base chains for input, forward, and output hooks are present"
    else
        echo -e "\n - Reason(s) for audit failure:$l_output2"
        [ -n "$l_output" ] && echo -e "\n - Correctly set:$l_output"
        log_fail "One or more nftables base chains ARE NOT present"
    fi
}

check_nftables_default_drop_policy() {
    print_header "4.3.3 - Ensure nftables default deny firewall policy"

    local l_output="" l_output2=""

    # Skip check if nftables is not active
    if ! rpm -q nftables > /dev/null 2>&1 || ! systemctl is-active nftables &>/dev/null; then
        log_pass "NFTables is not active — skipping default policy drop check"
        return
    fi

    local ruleset
    ruleset="$(nft list ruleset 2>/dev/null)"

    for hook in input forward; do
        if echo "$ruleset" | grep -E "hook $hook\b" | grep -qv "policy drop"; then
            l_output2+="\n - Default policy for $hook hook IS NOT set to DROP"
        else
            l_output+="\n - Default policy for $hook hook is correctly set to DROP"
        fi
    done

    if [ -z "$l_output2" ]; then
        echo -e "$l_output"
        log_pass "NFTables base chains for input and forward hooks are correctly set to DROP"
    else

        echo -e "\n - Reason(s) for audit failure:$l_output2"
        [ -n "$l_output" ] && echo -e "\n - Correctly set:$l_output"
        log_fail "One or more NFTables base chains ARE NOT set to default policy DROP"
    fi
}

check_nftables_loopback_traffic() {
    print_header "4.3.4 - Ensure nftables loopback traffic is configured"

    local l_output="" l_output2="" l_hbfw=""

    if systemctl is-enabled firewalld.service 2>/dev/null | grep -q 'enabled'; then
        log_pass "FirewallD is in use — this recommendation is Not Applicable"
        return
    elif systemctl is-enabled nftables.service 2>/dev/null | grep -q 'enabled'; then
        l_hbfw="nft"
    else
        log_fail "Neither FirewallD NOR NFTables IS enabled — only one should be configured"
        return
    fi

    if [ "$l_hbfw" = "nft" ]; then
        local ruleset="$(nft list ruleset 2>/dev/null)"

        # Check that input to lo is accepted
        if echo "$ruleset" | awk '/hook input/,/\}/' | grep -Pq '\b(lo|interface\s+"lo")\b.*\baccept\b'; then
            l_output+="\n - Loopback traffic to interface 'lo' is correctly set to ACCEPT"
        else
            l_output2+="\n - Loopback traffic to interface 'lo' IS NOT set to ACCEPT"
        fi

        # Check IPv4 from 127.0.0.0/8 is dropped
        local l_ipsaddr
        l_ipsaddr="$(echo "$ruleset" | awk '/filter_IN_public_deny|hook input/,/\}/' | grep -P 'ip\s+(saddr|daddr)')"

        if grep -Pq 'ip\s+saddr\s+127\.0\.0\.0/8.*\bdrop\b' <<< "$l_ipsaddr" || \
           grep -Pq 'ip\s+daddr\s+\!\=\s*127\.0\.0\.1\s+ip\s+saddr\s+127\.0\.0\.1\s+\bdrop\b' <<< "$l_ipsaddr"; then
            l_output+="\n - IPv4 loopback traffic from 127.0.0.0/8 is correctly set to DROP"
        else
            l_output2+="\n - IPv4 loopback traffic from 127.0.0.0/8 IS NOT set to DROP"
        fi

        # Check IPv6 loopback (::1) if IPv6 is enabled
        if [ "$(cat /sys/module/ipv6/parameters/disable)" = "0" ]; then
            local l_ip6saddr
            l_ip6saddr="$(echo "$ruleset" | awk '/filter_IN_public_deny|hook input/,/\}/' | grep 'ip6 saddr')"
            if grep -Pq 'ip6\s+saddr\s+::1.*\bdrop\b' <<< "$l_ip6saddr" || \
               grep -Pq 'ip6\s+daddr\s+\!\=\s*::1\s+ip6\s+saddr\s+::1\s+\bdrop\b' <<< "$l_ip6saddr"; then
                l_output+="\n - IPv6 loopback traffic from ::1 is correctly set to DROP"
            else
                l_output2+="\n - IPv6 loopback traffic from ::1 IS NOT set to DROP"
            fi
        fi
    fi

    # Final reporting
    if [ -z "$l_output2" ]; then
        echo -e "$l_output"
        log_pass "Loopback traffic is correctly configured in nftables"
    else
        echo -e "\n - Reason(s) for audit failure:$l_output2"
        [ -n "$l_output" ] && echo -e "\n - Correctly set:$l_output"
        log_fail "Loopback traffic IS NOT correctly configured in nftables"
    fi
}

check_sshd_config_permissions() {
    print_header "5.1.1 - Ensure permissions on /etc/ssh/sshd_config are configured"

    local l_output="" l_output2=""
    local perm_mask='0177'
    local maxperm
    maxperm="$(printf '%o' $((0777 & ~$perm_mask)))"

    check_file_attrs() {
        while IFS=: read -r l_mode l_user l_group; do
            local l_out2=""
            if [ $((l_mode & perm_mask)) -gt 0 ]; then
                l_out2+="\n  - Mode is \"$l_mode\", should be \"$maxperm\" or more restrictive"
            fi
            if [ "$l_user" != "root" ]; then
                l_out2+="\n  - Owner IS \"$l_user\", should be \"root\""
            fi
            if [ "$l_group" != "root" ]; then
                l_out2+="\n  - Group IS \"$l_group\", should be \"root\""
            fi
            if [ -n "$l_out2" ]; then
                l_output2+="\n - File: \"$l_file\":$l_out2"
            else
                l_output+="\n - File: \"$l_file\":\n  - Mode, owner, and group are correctly configured"
            fi
        done < <(stat -Lc '%#a:%U:%G' "$l_file")
    }

    # Check main sshd config file
    if [ -e "/etc/ssh/sshd_config" ]; then
        l_file="/etc/ssh/sshd_config"
        check_file_attrs
    fi

    # Check any config drop-in files under /etc/ssh/sshd_config.d/
    while IFS= read -r -d '' l_file; do
        [ -e "$l_file" ] && check_file_attrs
    done < <(find -L /etc/ssh/sshd_config.d -type f -print0 2>/dev/null)

    # Final output
    if [ -z "$l_output2" ]; then
        echo -e "$l_output"
        log_pass "All SSH configuration files have correct permissions and ownership"
    else
        echo -e "\n - Reason(s) for audit failure:$l_output2"
        [ -n "$l_output" ] && echo -e "\n - Correctly set:$l_output"
        log_fail "One or more SSH configuration files ARE NOT correctly configured"
    fi
}

check_ssh_private_key_permissions() {
    print_header "5.1.2 - Ensure permissions on SSH private host key files are configured "

    local l_output="" l_output2=""
    local l_ssh_group_name
    l_ssh_group_name="$(awk -F: '($1 ~ /^(ssh_keys|_?ssh)$/) {print $1}' /etc/group)"

    f_file_chk() {
        while IFS=: read -r l_file_mode l_file_owner l_file_group; do
            local l_out2=""
            local l_pmask
            [[ "$l_file_group" = "$l_ssh_group_name" ]] && l_pmask="0137" || l_pmask="0177"
            local l_maxperm
            l_maxperm="$(printf '%o' $((0777 & ~$l_pmask)))"

            if [ $((l_file_mode & l_pmask)) -gt 0 ]; then
                l_out2+="\n  - Mode IS \"$l_file_mode\", should be \"$l_maxperm\" or more restrictive"
            fi
            if [ "$l_file_owner" != "root" ]; then
                l_out2+="\n  - Owner IS \"$l_file_owner\", should be \"root\""
            fi
            if [[ ! "$l_file_group" =~ ^($l_ssh_group_name|root)$ ]]; then
                l_out2+="\n  - Group IS \"$l_file_group\", should be \"$l_ssh_group_name\" or \"root\""
            fi

            if [ -n "$l_out2" ]; then
                l_output2+="\n - File: \"$l_file\"$l_out2"
            else
                l_output+="\n - File: \"$l_file\"\n  - Correct: mode \"$l_file_mode\", owner \"$l_file_owner\", group \"$l_file_group\""
            fi
        done < <(stat -Lc '%#a:%U:%G' "$l_file")
    }

    while IFS= read -r -d '' l_file; do
        if ssh-keygen -lf "$l_file" &>/dev/null; then
            if file "$l_file" | grep -Piq '\bOpenSSH\b.*\bprivate key\b'; then
                f_file_chk
            fi
        fi
    done < <(find -L /etc/ssh -xdev -type f -print0 2>/dev/null)

    if [ -z "$l_output2" ]; then
        [ -z "$l_output" ] && l_output="\n  - No OpenSSH private keys found"
        echo -e "$l_output"
        log_pass "All OpenSSH private host keys are correctly configured"
    else
        echo -e "\n - Reason(s) for audit failure:$l_output2"
        [ -n "$l_output" ] && echo -e "\n - Correctly configured:$l_output"
        log_fail "One or more OpenSSH private host keys ARE NOT correctly configured"
    fi
}

check_ssh_public_key_permissions() {
    print_header "5.1.3 - Ensure permissions on SSH public host key files are configured "

    local l_output="" l_output2=""
    local l_pmask="0133"
    local l_maxperm
    l_maxperm="$(printf '%o' $((0777 & ~$l_pmask)))"

    check_file_attrs() {
        while IFS=: read -r l_file_mode l_file_owner l_file_group; do
            local l_out2=""

            if [ $((l_file_mode & l_pmask)) -gt 0 ]; then
                l_out2+="\n  - Mode IS \"$l_file_mode\", should be \"$l_maxperm\" or more restrictive"
            fi
            if [ "$l_file_owner" != "root" ]; then
                l_out2+="\n  - Owner IS \"$l_file_owner\", should be \"root\""
            fi
            if [ "$l_file_group" != "root" ]; then
                l_out2+="\n  - Group IS \"$l_file_group\", should be \"root\""
            fi

            if [ -n "$l_out2" ]; then
                l_output2+="\n - File: \"$l_file\"$l_out2"
            else
                l_output+="\n - File: \"$l_file\"\n  - Correct: mode \"$l_file_mode\", owner \"$l_file_owner\", group \"$l_file_group\""
            fi
        done < <(stat -Lc '%#a:%U:%G' "$l_file")
    }

    while IFS= read -r -d '' l_file; do
        if ssh-keygen -lf "$l_file" &>/dev/null; then
            if file "$l_file" | grep -Piq '\bOpenSSH\b.*\bpublic key\b'; then
                check_file_attrs
            fi
        fi
    done < <(find -L /etc/ssh -xdev -type f -print0 2>/dev/null)

    if [ -z "$l_output2" ]; then
        [ -z "$l_output" ] && l_output="\n  - No OpenSSH public keys found"
        echo -e "$l_output"
        log_pass "All OpenSSH public host keys are correctly configured"
    else
        echo -e "\n - Reason(s) for audit failure:$l_output2"
        [ -n "$l_output" ] && echo -e "\n - Correctly configured:$l_output"
        log_fail "One or more OpenSSH public host keys ARE NOT correctly configured"
    fi
}

check_sshd_ciphers_strength() {
    print_header "5.1.4 - Ensure sshd Ciphers are configured"

    local l_output="" l_output2=""
    local weak_ciphers_regex='^ciphers\h+\"?([^#\n\r]+,)?((3des|blowfish|cast128|aes(128|192|256))cbc|arcfour(128|256)?|rijndael-cbc@lysator\.liu\.se|chacha20-poly1305@openssh\.com)\b'

    if ! command -v sshd &>/dev/null; then
        log_fail "sshd IS NOT installed or not in PATH"
        return
    fi

    local cipher_output
    cipher_output="$(sshd -T 2>/dev/null | grep -Pi "$weak_ciphers_regex")"

    if [ -n "$cipher_output" ]; then
        l_output2+="\n - Found insecure cipher configuration:\n$cipher_output"
        log_fail "Weak or legacy ciphers ARE configured in sshd"
    else
        l_output+="\n - No insecure ciphers found in sshd configuration"
        log_pass "Only strong SSH ciphers are configured in sshd"
    fi

    # Final output
    if [ -n "$l_output2" ]; then
        echo -e "\n - Reason(s) for audit failure:$l_output2"
    fi
    if [ -n "$l_output" ]; then
        echo -e "$l_output"
    fi
}

check_sshd_kexalgorithms_strength() {
    print_header "5.1.5 - Ensure sshd KexAlgorithms is configured"

    local l_output="" l_output2=""
    local weak_kex_regex='kexalgorithms\h+([^#\n\r]+,)?(diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1)\b'

    if ! command -v sshd &>/dev/null; then
        log_fail "sshd IS NOT installed or not in PATH"
        return
    fi

    local kex_output
    kex_output="$(sshd -T 2>/dev/null | grep -Pi "$weak_kex_regex")"

    if [ -n "$kex_output" ]; then
        l_output2+="\n - Found insecure KexAlgorithms configuration:\n$kex_output"
        log_fail "Weak SSH Key Exchange algorithms ARE configured in sshd"
    else
        l_output+="\n - No weak KexAlgorithms found in sshd configuration"
        log_pass "Only strong SSH Key Exchange algorithms are configured in sshd"
    fi

    # Final output
    if [ -n "$l_output2" ]; then
        echo -e "\n - Reason(s) for audit failure:$l_output2"
    fi
    if [ -n "$l_output" ]; then
        echo -e "$l_output"
    fi
}

check_sshd_macs_strength() {
    print_header "5.1.6 - Ensure sshd MACs are configured"

    local l_output="" l_output2=""
    local weak_mac_regex='macs\h+([^#\n\r]+,)?(hmac-md5|hmac-md5-96|hmac-ripemd160|hmac-sha1-96|umac-64@openssh\.com|hmac-md5-etm@openssh\.com|hmac-md5-96-etm@openssh\.com|hmac-ripemd160-etm@openssh\.com|hmac-sha1-96-etm@openssh\.com|umac-64-etm@openssh\.com|umac-128-etm@openssh\.com)\b'

    if ! command -v sshd &>/dev/null; then
        log_fail "sshd IS NOT installed or not in PATH"
        return
    fi

    local mac_output
    mac_output="$(sshd -T 2>/dev/null | grep -Pi "$weak_mac_regex")"

    if [ -n "$mac_output" ]; then
        l_output2+="\n - Found insecure MACs configuration:\n$mac_output"
        log_fail "Weak SSH MAC algorithms ARE configured in sshd"
    else
        l_output+="\n - No weak MACs found in sshd configuration"
        log_pass "Only strong SSH MAC algorithms are configured in sshd"
    fi

    # Final output
    if [ -n "$l_output2" ]; then
        echo -e "\n - Reason(s) for audit failure:$l_output2"
    fi
    if [ -n "$l_output" ]; then
        echo -e "$l_output"
    fi
}

check_sshd_access_controls() {
    print_header "5.1.7 - Ensure sshd access is configured"

    local l_output="" l_output2=""
    local access_control_output

    access_control_output="$(sshd -T 2>/dev/null | grep -Pi '^\s*(allow|deny)(users|groups)\s+\S+')"

    if [ -n "$access_control_output" ]; then
        l_output+="\n - Found directive(s):\n$access_control_output"
        log_pass "SSHD access control directives are properly configured"
    else
        l_output2+="\n - No AllowUsers, AllowGroups, DenyUsers, or DenyGroups directives were found"
        log_fail "SSHD access control directives ARE NOT configured"
    fi

    # Final output
    if [ -n "$l_output2" ]; then
        echo -e "\n - Reason(s) for audit failure:$l_output2"
    fi
    if [ -n "$l_output" ]; then
        echo -e "$l_output"
    fi
}

check_sshd_banner_configured() {
    print_header "5.1.8 - Ensure sshd Banner is configured"

    local l_output="" l_output2=""
    local banner_output

    banner_output="$(sshd -T 2>/dev/null | grep -Pi '^banner\s+/\S+')"

    if [ -n "$banner_output" ]; then
        l_output+="\n - Found Banner directive:\n$banner_output"
        log_pass "SSH warning banner IS configured"
    else
        l_output2+="\n - Missing or invalid Banner directive in sshd_config"
        log_fail "SSH warning banner IS NOT configured"
    fi

    # Final output
    if [ -n "$l_output2" ]; then
        echo -e "\n - Reason(s) for audit failure:$l_output2"
    fi
    if [ -n "$l_output" ]; then
        echo -e "$l_output"
    fi
}

check_sshd_idle_timeout() {
    print_header "5.1.9 - Ensure sshd ClientAliveInterval and ClientAliveCountMax are configured"

    local l_output="" l_output2=""
    local client_alive_interval client_alive_countmax

    client_alive_interval="$(sshd -T 2>/dev/null | grep -Pi '^clientaliveinterval\b')"
    client_alive_countmax="$(sshd -T 2>/dev/null | grep -Pi '^clientalivecountmax\b')"

    if [ -n "$client_alive_interval" ]; then
        l_output+="\n - $client_alive_interval"
    else
        l_output2+="\n - ClientAliveInterval IS NOT set"
    fi

    if [ -n "$client_alive_countmax" ]; then
        l_output+="\n - $client_alive_countmax"
    else
        l_output2+="\n - ClientAliveCountMax IS NOT set"
    fi

    if [ -z "$l_output2" ]; then
        echo -e "$l_output"
        log_pass "SSH idle timeout settings ARE configured"
    else
        echo -e "\n - Reason(s) for audit failure:$l_output2"
        [ -n "$l_output" ] && echo -e "\n - Correctly set:$l_output"
        log_fail "SSH idle timeout settings ARE NOT fully configured"
    fi
}

check_sshd_hostbased_authentication() {
    print_header "5.1.12 - Ensure sshd HostbasedAuthentication is disabled "

    local l_output="" l_output2=""
    local hba_setting

    hba_setting="$(sshd -T 2>/dev/null | grep -Pi '^hostbasedauthentication\b')"

    if [ -z "$hba_setting" ]; then
        log_fail "HostbasedAuthentication IS NOT explicitly set in sshd_config"
        l_output2+="\n - Missing HostbasedAuthentication directive (default may be insecure on some systems)"
    elif grep -Piq '^hostbasedauthentication\s+no' <<< "$hba_setting"; then
        l_output+="\n - $hba_setting"
        log_pass "HostbasedAuthentication IS disabled as required"
    else
        l_output2+="\n - $hba_setting"
        log_fail "HostbasedAuthentication IS enabled"
    fi

    # Final output
    if [ -n "$l_output2" ]; then
        echo -e "\n - Reason(s) for audit failure:$l_output2"
    fi
    if [ -n "$l_output" ]; then
        echo -e "$l_output"
    fi
}

check_sshd_ignore_rhosts() {
    print_header "5.1.13 - Ensure sshd IgnoreRhosts is enabled"

    local l_output="" l_output2=""
    local ignore_rhosts_setting

    ignore_rhosts_setting="$(sshd -T 2>/dev/null | grep -Pi '^ignorerhosts\b')"

    if [ -z "$ignore_rhosts_setting" ]; then
        log_fail "IgnoreRhosts IS NOT explicitly set in sshd_config"
        l_output2+="\n - Missing IgnoreRhosts directive (default may be unsafe on some systems)"
    elif grep -Piq '^ignorerhosts\s+yes' <<< "$ignore_rhosts_setting"; then
        l_output+="\n - $ignore_rhosts_setting"
        log_pass "IgnoreRhosts IS enabled as required"
    else
        l_output2+="\n - $ignore_rhosts_setting"
        log_fail "IgnoreRhosts IS disabled"
    fi

    # Final output
    if [ -n "$l_output2" ]; then
        echo -e "\n - Reason(s) for audit failure:$l_output2"
    fi
    if [ -n "$l_output" ]; then
        echo -e "$l_output"
    fi
}

check_sshd_login_grace_time() {
    print_header "5.1.14 - Ensure sshd LoginGraceTime is configured"

    local l_output="" l_output2=""
    local login_grace_time

    login_grace_time="$(sshd -T 2>/dev/null | grep -Pi '^logingracetime\b' | awk '{print $2}')"

    if [ -z "$login_grace_time" ]; then
        log_fail "LoginGraceTime IS NOT explicitly set in sshd_config"
        l_output2+="\n - Missing LoginGraceTime directive"
    elif [[ "$login_grace_time" =~ ^[0-9]+$ ]] && [ "$login_grace_time" -ge 1 ] && [ "$login_grace_time" -le 60 ]; then
        l_output+="\n - logingracetime $login_grace_time"
        log_pass "LoginGraceTime IS set correctly to $login_grace_time seconds"
    else
        l_output2+="\n - logingracetime $login_grace_time (must be between 1 and 60)"
        log_fail "LoginGraceTime IS set to an invalid value: $login_grace_time"
    fi

    # Final output
    if [ -n "$l_output2" ]; then
        echo -e "\n - Reason(s) for audit failure:$l_output2"
    fi
    if [ -n "$l_output" ]; then
        echo -e "$l_output"
    fi
}

check_sshd_loglevel() {
    print_header "5.1.15 Ensure sshd LogLevel is configured"

    local l_output="" l_output2=""
    local loglevel_value

    loglevel_value="$(sshd -T 2>/dev/null | grep -Pi '^loglevel\b' | awk '{print tolower($2)}')"

    if [ -z "$loglevel_value" ]; then
        log_fail "LogLevel IS NOT explicitly set in sshd_config"
        l_output2+="\n - Missing LogLevel directive"
    elif [[ "$loglevel_value" == "info" || "$loglevel_value" == "verbose" ]]; then
        l_output+="\n - loglevel $loglevel_value"
        log_pass "LogLevel IS set correctly to \"$loglevel_value\""
    else
        l_output2+="\n - loglevel $loglevel_value (must be INFO or VERBOSE)"
        log_fail "LogLevel IS set to an unacceptable value: \"$loglevel_value\""
    fi

    # Final output
    if [ -n "$l_output2" ]; then
        echo -e "\n - Reason(s) for audit failure:$l_output2"
    fi
    if [ -n "$l_output" ]; then
        echo -e "$l_output"
    fi
}

check_sshd_max_auth_tries() {
    print_header "5.1.16 - Ensure sshd MaxAuthTries is configured"

    local l_output="" l_output2=""
    local max_auth_tries

    max_auth_tries="$(sshd -T 2>/dev/null | grep -Pi '^maxauthtries\b' | awk '{print $2}')"

    if [ -z "$max_auth_tries" ]; then
        log_fail "MaxAuthTries IS NOT explicitly set in sshd_config"
        l_output2+="\n - Missing MaxAuthTries directive"
    elif [[ "$max_auth_tries" =~ ^[0-9]+$ ]] && [ "$max_auth_tries" -le 4 ]; then
        l_output+="\n - maxauthtries $max_auth_tries"
        log_pass "MaxAuthTries IS set correctly to $max_auth_tries"
    else
        l_output2+="\n - maxauthtries $max_auth_tries (must be 4 or less)"
        log_fail "MaxAuthTries IS set to an unacceptable value: $max_auth_tries"
    fi

    # Final output
    if [ -n "$l_output2" ]; then
        echo -e "\n - Reason(s) for audit failure:$l_output2"
    fi
    if [ -n "$l_output" ]; then
        echo -e "$l_output"
    fi
}

check_sshd_max_startups() {
    print_header "5.1.17 - Ensure sshd MaxStartups is configured"

    local l_output="" l_output2=""
    local maxstartups_line
    local start rate full

    maxstartups_line="$(sshd -T 2>/dev/null | awk '$1 ~ /^maxstartups/ {print $2}')"

    if [ -z "$maxstartups_line" ]; then
        log_pass "MaxStartups IS NOT explicitly set — default values are assumed safe"
        return
    fi

    IFS=':' read -r start rate full <<< "$maxstartups_line"

    # Assign defaults if only one or two fields are present
    start="${start:-10}"
    rate="${rate:-30}"
    full="${full:-60}"

    if [ "$start" -le 10 ] && [ "$rate" -le 30 ] && [ "$full" -le 60 ]; then
        l_output+="\n - maxstartups $start:$rate:$full"
        log_pass "MaxStartups IS set within acceptable limits"
    else
        l_output2+="\n - maxstartups $start:$rate:$full (must be ≤ 10:30:60)"
        log_fail "MaxStartups IS set to unacceptable values"
    fi

    # Final output
    if [ -n "$l_output2" ]; then
        echo -e "\n - Reason(s) for audit failure:$l_output2"
    fi
    if [ -n "$l_output" ]; then
        echo -e "$l_output"
    fi
}

check_sshd_max_sessions() {
    print_header "5.1.18 - Ensure sshd MaxSessions is configured"

    local l_output="" l_output2=""
    local max_sessions runtime_issue config_issue

    # Check runtime (effective) value
    max_sessions="$(sshd -T 2>/dev/null | grep -i '^maxsessions' | awk '{print $2}')"

    if [ -z "$max_sessions" ]; then
        l_output2+="\n - Missing MaxSessions directive in sshd runtime output"
        runtime_issue=1
        log_fail "MaxSessions IS NOT explicitly set in effective configuration"
    elif [[ "$max_sessions" =~ ^[0-9]+$ ]] && [ "$max_sessions" -le 10 ]; then
        l_output+="\n - Runtime setting: maxsessions $max_sessions"
    else
        l_output2+="\n - Runtime setting: maxsessions $max_sessions (must be 10 or less)"
        runtime_issue=1
        log_fail "MaxSessions IS set to an unacceptable value in runtime: $max_sessions"
    fi

    # Check config files for values > 10
    local config_matches
    config_matches="$(grep -Psi -- '^\h*MaxSessions\h+\"?(1[1-9]|[2-9][0-9]|[1-9][0-9]{2,})\b' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null)"

    if [ -n "$config_matches" ]; then
        l_output2+="\n - Found invalid MaxSessions settings in config:\n$config_matches"
        config_issue=1
        log_fail "One or more SSH configuration files SET MaxSessions to a value greater than 10"
    else
        l_output+="\n - No invalid MaxSessions values found in sshd configuration files"
    fi

    # Final result
    if [ "$runtime_issue" != 1 ] && [ "$config_issue" != 1 ]; then
        echo -e "$l_output"
        log_pass "MaxSessions IS correctly configured in both runtime and configuration files"
    else
        echo -e "\n - Reason(s) for audit failure:$l_output2"
        [ -n "$l_output" ] && echo -e "\n - Correctly set:$l_output"
    fi
}

check_sshd_permit_empty_passwords() {
    print_header "5.1.19 - Ensure sshd PermitEmptyPasswords is disabled"

    local l_output="" l_output2=""
    local permit_empty_passwords

    permit_empty_passwords="$(sshd -T 2>/dev/null | grep -Pi '^permitemptypasswords\b' | awk '{print tolower($2)}')"

    if [ -z "$permit_empty_passwords" ]; then
        l_output2+="\n - Missing PermitEmptyPasswords directive"
        log_fail "PermitEmptyPasswords IS NOT explicitly set in sshd_config"
    elif [ "$permit_empty_passwords" = "no" ]; then
        l_output+="\n - permitemptypasswords $permit_empty_passwords"
        log_pass "PermitEmptyPasswords IS set to \"no\" as required"
    else
        l_output2+="\n - permitemptypasswords $permit_empty_passwords"
        log_fail "PermitEmptyPasswords IS set to \"$permit_empty_passwords\" (should be \"no\")"
    fi

    # Final output
    if [ -n "$l_output2" ]; then
        echo -e "\n - Reason(s) for audit failure:$l_output2"
    fi
    if [ -n "$l_output" ]; then
        echo -e "$l_output"
    fi
}

check_sshd_permit_root_login() {
    print_header "5.1.20 - Ensure sshd PermitRootLogin is disabled "

    local l_output="" l_output2=""
    local permit_root_login

    permit_root_login="$(sshd -T 2>/dev/null | grep -Pi '^permitrootlogin\b' | awk '{print tolower($2)}')"

    if [ -z "$permit_root_login" ]; then
        l_output2+="\n - Missing PermitRootLogin directive"
        log_fail "PermitRootLogin IS NOT explicitly set in sshd_config"
    elif [ "$permit_root_login" = "no" ]; then
        l_output+="\n - permitrootlogin $permit_root_login"
        log_pass "PermitRootLogin IS set to \"no\" as required"
    else
        l_output2+="\n - permitrootlogin $permit_root_login"
        log_fail "PermitRootLogin IS set to \"$permit_root_login\" (should be \"no\")"
    fi

    # Final output
    if [ -n "$l_output2" ]; then
        echo -e "\n - Reason(s) for audit failure:$l_output2"
    fi
    if [ -n "$l_output" ]; then
        echo -e "$l_output"
    fi
}

check_sshd_permit_user_environment() {
    print_header "5.1.21 - Ensure sshd PermitUserEnvironment is disabled"

    local l_output="" l_output2=""
    local permit_user_env

    permit_user_env="$(sshd -T 2>/dev/null | grep -Pi '^permituserenvironment\b' | awk '{print tolower($2)}')"

    if [ -z "$permit_user_env" ]; then
        l_output2+="\n - Missing PermitUserEnvironment directive"
        log_fail "PermitUserEnvironment IS NOT explicitly set in sshd_config"
    elif [ "$permit_user_env" = "no" ]; then
        l_output+="\n - permituserenvironment $permit_user_env"
        log_pass "PermitUserEnvironment IS set to \"no\" as required"
    else
        l_output2+="\n - permituserenvironment $permit_user_env"
        log_fail "PermitUserEnvironment IS set to \"$permit_user_env\" (should be \"no\")"
    fi

    # Final output
    if [ -n "$l_output2" ]; then
        echo -e "\n - Reason(s) for audit failure:$l_output2"
    fi
    if [ -n "$l_output" ]; then
        echo -e "$l_output"
    fi
}

check_sshd_use_pam() {
    print_header "5.1.22 - Ensure sshd UsePAM is enabled "

    local l_output="" l_output2=""
    local use_pam

    use_pam="$(sshd -T 2>/dev/null | grep -Pi '^usepam\b' | awk '{print tolower($2)}')"

    if [ -z "$use_pam" ]; then
        l_output2+="\n - Missing UsePAM directive"
        log_fail "UsePAM IS NOT explicitly set in sshd_config"
    elif [ "$use_pam" = "yes" ]; then
        l_output+="\n - usepam $use_pam"
        log_pass "UsePAM IS set to \"yes\" as required"
    else
        l_output2+="\n - usepam $use_pam"
        log_fail "UsePAM IS set to \"$use_pam\" (should be \"yes\")"
    fi

    # Final output
    if [ -n "$l_output2" ]; then
        echo -e "\n - Reason(s) for audit failure:$l_output2"
    fi
    if [ -n "$l_output" ]; then
        echo -e "$l_output"
    fi
}

check_sudo_installed() {
    print_header "5.2.1 - Ensure 'sudo' is installed"

    local l_output="" l_output2=""
    local sudo_status

    sudo_status="$(dnf list installed sudo 2>/dev/null | grep -Pi '^sudo\.\S+\s+')"

    if [ -n "$sudo_status" ]; then
        l_output+="\n - Installed Package:\n$sudo_status"
        log_pass "'sudo' package IS installed"
    else
        l_output2+="\n - 'sudo' is not present in the installed package list"
        log_fail "'sudo' package IS NOT installed"
    fi

    # Final output
    if [ -n "$l_output2" ]; then
        echo -e "\n - Reason(s) for audit failure:$l_output2"
    fi
    if [ -n "$l_output" ]; then
        echo -e "$l_output"
    fi
}

check_sudo_use_pty() {
    print_header "5.2.2 - Ensure sudo commands use pty"

    local l_output="" l_output2=""
    local sudo_pty_setting

    # Search for "Defaults use_pty" line explicitly (no negation, no override)
    sudo_pty_setting="$(grep -rPi -- '^\h*Defaults\h+(.*,\h*)?use_pty\b' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -v '^#')"

    if echo "$sudo_pty_setting" | grep -q '^/etc/sudoers:.*use_pty'; then
        l_output+="\n - $sudo_pty_setting"
        log_pass "Defaults use_pty IS configured in /etc/sudoers"
    else
        if [ -n "$sudo_pty_setting" ]; then
            l_output2+="\n - Found in non-standard location:\n$sudo_pty_setting"
        else
            l_output2+="\n - 'Defaults use_pty' not found in /etc/sudoers or included configs"
        fi
        log_fail "Defaults use_pty IS NOT configured properly in /etc/sudoers"
    fi

    # Final output
    if [ -n "$l_output2" ]; then
        echo -e "\n - Reason(s) for audit failure:$l_output2"
    fi
    if [ -n "$l_output" ]; then
        echo -e "$l_output"
    fi
}

check_sudo_logfile_defined() {
    print_header "5.2.3 - Ensure sudo log file is configured"

    local l_output="" l_output2=""
    local sudo_logfile_setting

    sudo_logfile_setting="$(grep -rPsi '^\h*Defaults\h+([^#]+,\h*)?logfile\h*=\h*(\"|\')?\H+(\"|\')?(,\h*\H+\h*)*\h*(#.*)?$' /etc/sudoers /etc/sudoers.d/* 2>/dev/null)"

    if [ -n "$sudo_logfile_setting" ]; then
        l_output+="\n - $sudo_logfile_setting"
        log_pass "Defaults logfile IS defined for sudo"
    else
        l_output2+="\n - 'Defaults logfile=' not found in /etc/sudoers or included files"
        log_fail "Defaults logfile IS NOT configured for sudo"
    fi

    # Final output
    if [ -n "$l_output2" ]; then
        echo -e "\n - Reason(s) for audit failure:$l_output2"
    fi
    if [ -n "$l_output" ]; then
        echo -e "$l_output"
    fi
}

check_sudo_authentication_required() {
    print_header "5.2.5 - Ensure re-authentication for privilege escalation is not disabled globally"

    local l_output="" l_output2=""
    local matches

    matches="$(grep -rP '^[^#].*\!authenticate' /etc/sudoers /etc/sudoers.d/* 2>/dev/null)"

    if [ -z "$matches" ]; then
        l_output+="\n - All sudo commands require authentication"
        log_pass "No 'NOPASSWD' or '!authenticate' directives found in sudoers"
    else
        l_output2+="\n - Found the following occurrences:\n$matches"
        log_fail "'!authenticate' IS present in sudo configuration"
    fi

    # Final output
    if [ -n "$l_output2" ]; then
        echo -e "\n - Reason(s) for audit failure:$l_output2"
    fi
    if [ -n "$l_output" ]; then
        echo -e "$l_output"
    fi
}

check_sudo_timestamp_timeout() {
    print_header "5.2.6 - Ensure sudo authentication timeout is configured correctly"

    local l_output="" l_output2=""
    local defined_timeouts default_timeout
    local valid=true

    # Check for explicitly set timestamp_timeout values
    defined_timeouts=$(grep -roP "timestamp_timeout=\K[0-9]+" /etc/sudoers /etc/sudoers.d/* 2>/dev/null)

    if [ -n "$defined_timeouts" ]; then
        while read -r timeout; do
            if [ "$timeout" -gt 15 ]; then
                valid=false
                l_output2+="\n - Found timestamp_timeout=$timeout (exceeds 15 minutes)"
            else
                l_output+="\n - Found timestamp_timeout=$timeout (compliant)"
            fi
        done <<< "$defined_timeouts"
    else
        # No override found — check default from sudo -V
        default_timeout=$(sudo -V | grep -Pi "Authentication timestamp timeout" | grep -oP '\d+')
        if [ "$default_timeout" -le 15 ]; then
            l_output+="\n - Authentication timestamp timeout: $default_timeout minutes"
            log_pass "Default sudo timestamp timeout IS set to $default_timeout minutes (compliant)"
        else
            l_output2+="\n - Authentication timestamp timeout: $default_timeout minutes"
            log_fail "Default sudo timestamp timeout IS set to $default_timeout minutes (must be 15 or less)"
        fi
    fi

    # Final output
    if [ "$valid" = false ]; then
        echo -e "\n - Reason(s) for audit failure:$l_output2"
        [ -n "$l_output" ] && echo -e "\n - Correctly set:$l_output"
        log_fail "One or more sudo timestamp timeouts ARE NOT compliant"
    elif [ -z "$l_output2" ]; then
        echo -e "$l_output"
        log_pass "All sudo timestamp timeouts ARE compliant (≤ 15 minutes)"
    fi
}

check_su_restriction_via_pam_wheel() {
    print_header "5.2.7 - Ensure access to the su command is restricted"

    local l_output="" l_output2=""
    local pam_line group_name group_line

    # Get pam_wheel.so line that includes both use_uid and group=*
    pam_line=$(grep -Pi '^\h*auth\h+(required|requisite)\h+pam_wheel\.so\h+.*\buse_uid\b.*\bgroup=\H+' /etc/pam.d/su)

    if [ -n "$pam_line" ]; then
        group_name=$(echo "$pam_line" | grep -oP 'group=\K\H+')
        l_output+="\n - $pam_line"
        log_pass "pam_wheel.so IS properly configured in /etc/pam.d/su"

        # Validate the group exists and contains no users
        group_line=$(grep -P "^${group_name}:" /etc/group)

        if [ -z "$group_line" ]; then
            l_output2+="\n - Group \"$group_name\" not found in /etc/group"
            log_fail "Group '$group_name' IS NOT defined in /etc/group"
        elif echo "$group_line" | awk -F: '{print $4}' | grep -vq '^$'; then
            l_output2+="\n - Group \"$group_name\" contains users:\n$group_line"
            log_fail "Group '$group_name' IS NOT empty"
        else
            l_output+="\n - $group_line"
            log_pass "Group '$group_name' IS defined and contains no users"
        fi
    else
        l_output2+="\n - Line with both 'use_uid' and 'group=' NOT found in /etc/pam.d/su"
        log_fail "pam_wheel.so IS NOT properly configured in /etc/pam.d/su"
    fi

    # Final output
    if [ -n "$l_output2" ]; then
        echo -e "\n - Reason(s) for audit failure:$l_output2"
    fi
    if [ -n "$l_output" ]; then
        echo -e "$l_output"
    fi
}

check_pam_modules_in_authselect() {
    print_header "5.3.2.1 - Ensure active authselect profile includes pam modules"

    local l_output="" l_output2=""
    local profile_path modules_found

    # Get active authselect profile name
    profile_path="$(head -1 /etc/authselect/authselect.conf 2>/dev/null)"

    if [ -z "$profile_path" ]; then
        l_output2+="\n - File /etc/authselect/authselect.conf is missing or empty"
        log_fail "Unable to determine active authselect profile FROM /etc/authselect/authselect.conf"
    else
        modules_found=$(grep -P -- '\b(pam_pwquality\.so|pam_pwhistory\.so|pam_faillock\.so|pam_unix\.so)\b' \
            /etc/authselect/"$profile_path"/{system,password}-auth 2>/dev/null)

        if [ -n "$modules_found" ]; then
            l_output+="\n - Found modules:\n$modules_found"
            log_pass "One or more required PAM modules ARE present in active authselect profile"
        else
            l_output2+="\n - Expected pam modules not found in: /etc/authselect/$profile_path/"
            log_fail "Required PAM modules ARE NOT found in authselect profile"
        fi
    fi

    # Final output
    if [ -n "$l_output2" ]; then
        echo -e "\n - Reason(s) for audit failure:$l_output2"
    fi
    if [ -n "$l_output" ]; then
        echo -e "$l_output"
    fi
}

check_pam_faillock_module() {
    print_header "5.3.2.2 - Ensure pam_faillock module is enabled "

    local l_output="" l_output2=""
    local faillock_matches

    faillock_matches=$(grep -P -- '\bpam_faillock\.so\b' /etc/pam.d/{system,password}-auth 2>/dev/null)

    if [ -n "$faillock_matches" ]; then
        l_output+="\n - Found references:\n$faillock_matches"
        log_pass "pam_faillock.so IS present in system-auth and/or password-auth"
    else
        l_output2+="\n - No references to pam_faillock.so found in PAM files"
        log_fail "pam_faillock.so IS NOT configured in system-auth or password-auth"
    fi

    # Final output
    if [ -n "$l_output2" ]; then
        echo -e "\n - Reason(s) for audit failure:$l_output2"
    fi
    if [ -n "$l_output" ]; then
        echo -e "$l_output"
    fi
}

check_pam_pwquality_module() {
    print_header "5.3.2.3 - Ensure pam_pwquality module is enabled"

    local l_output="" l_output2=""
    local matches

    matches=$(grep -P -- '\bpam_pwquality\.so\b' /etc/pam.d/{system,password}-auth 2>/dev/null)

    if [ -n "$matches" ]; then
        l_output+="\n - Found references:\n$matches"
        log_pass "pam_pwquality.so IS present in system-auth and/or password-auth"

        # Optionally check for 'local_users_only'
        if echo "$matches" | grep -vq 'local_users_only'; then
            l_output2+="\n - Warning: pam_pwquality.so is present but does NOT include 'local_users_only'"
        fi
    else
        l_output2+="\n - No references to pam_pwquality.so found in PAM files"
        log_fail "pam_pwquality.so IS NOT configured in system-auth or password-auth"
    fi

    # Final output
    if [ -n "$l_output2" ]; then
        echo -e "\n - Reason(s) for audit warning/failure:$l_output2"
    fi
    if [ -n "$l_output" ]; then
        echo -e "$l_output"
    fi
}

check_pam_pwhistory_module() {
    print_header "5.3.2.4 - Ensure pam_pwhistory module is enabled"

    local l_output="" l_output2=""
    local matches
    local file

    matches=$(grep -P -- '\bpam_pwhistory\.so\b' /etc/pam.d/{system,password}-auth 2>/dev/null)

    if [ -n "$matches" ]; then
        l_output+="\n - Found references:\n$matches"
        log_pass "pam_pwhistory.so IS present in system-auth and/or password-auth"

        # Check that both files have use_authtok
        for file in /etc/pam.d/system-auth /etc/pam.d/password-auth; do
            if ! grep -Pq '^password\s+required\s+pam_pwhistory\.so.*\buse_authtok\b' "$file"; then
                l_output2+="\n - $file: pam_pwhistory.so line is missing 'use_authtok'"
                log_fail "pam_pwhistory.so in $file IS missing required argument 'use_authtok'"
            fi
        done
    else
        l_output2+="\n - No references to pam_pwhistory.so found"
        log_fail "pam_pwhistory.so IS NOT configured in system-auth or password-auth"
    fi

    # Final output
    if [ -n "$l_output2" ]; then
        echo -e "\n - Reason(s) for audit failure:$l_output2"
    fi
    if [ -n "$l_output" ]; then
        echo -e "$l_output"
    fi
}

check_pam_unix_module() {
    print_header "5.3.2.5 - Ensure pam_unix module is enabled"

    local l_output="" l_output2=""
    local file context required_line
    local contexts=("auth" "account" "password" "session")
    local files=("/etc/pam.d/system-auth" "/etc/pam.d/password-auth")

    for file in "${files[@]}"; do
        for context in "${contexts[@]}"; do
            required_line=$(grep -P "^\s*${context}\s+\S+\s+pam_unix\.so" "$file" 2>/dev/null)
            if [ -n "$required_line" ]; then
                l_output+="\n - [$file] $required_line"
            else
                l_output2+="\n - $file: missing pam_unix.so entry for context '$context'"
                log_fail "pam_unix.so IS MISSING in [$file] context: $context"
            fi
        done
    done

    # Final output
    if [ -n "$l_output2" ]; then
        echo -e "\n - Reason(s) for audit failure:$l_output2"
    else
        log_pass "pam_unix.so IS present in all required contexts and files"
    fi

    [ -n "$l_output" ] && echo -e "$l_output"
}

check_faillock_deny_setting() {
    print_header "5.3.3.1.1 - Ensure password failed attempts lockout is configured"

    local l_output="" l_output2=""
    local faillock_deny pam_override

    # Check faillock.conf (preferred method)
    faillock_deny=$(grep -Pi -- '^\h*deny\h*=\h*[1-5]\b' /etc/security/faillock.conf 2>/dev/null)

    if [ -n "$faillock_deny" ]; then
        l_output+="\n - $faillock_deny"
        log_pass "deny setting in faillock.conf IS set to 5 or less"
    else
        l_output2+="\n - deny line not found or set above 5 in /etc/security/faillock.conf"
        log_fail "deny setting in faillock.conf IS NOT properly configured (missing or > 5)"
    fi

    # Check for PAM overrides that are non-compliant (deny > 5)
    pam_override=$(grep -Pi -- '^\h*auth\h+(requisite|required|sufficient)\h+pam_faillock\.so\h+([^#\n\r]+\h+)?deny\h*=\h*(0|[6-9]|[1-9][0-9]+)\b' /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null)

    if [ -n "$pam_override" ]; then
        l_output2+="\n - Found non-compliant deny setting in PAM:\n$pam_override"
        log_fail "deny setting override IS present in PAM configuration and IS set above 5"
    fi

    # Final Output
    if [ -n "$l_output2" ]; then
        echo -e "\n - Reason(s) for audit failure:$l_output2"
    fi
    if [ -n "$l_output" ]; then
        echo -e "$l_output"
    fi
}

check_faillock_unlock_time() {
    print_header "5.3.3.1.2 - Ensure password unlock time is configured"

    local l_output="" l_output2=""
    local faillock_unlock pam_override

    # Check faillock.conf (preferred method)
    faillock_unlock=$(grep -Pi -- '^\h*unlock_time\h*=\h*(0|9[0-9][0-9]|[1-9][0-9]{3,})\b' /etc/security/faillock.conf 2>/dev/null)

    if [ -n "$faillock_unlock" ]; then
        l_output+="\n - $faillock_unlock"
        log_pass "unlock_time in faillock.conf IS set to a compliant value (0 or ≥900)"
    else
        l_output2+="\n - unlock_time not found or set to non-compliant value in faillock.conf"
        log_fail "unlock_time in faillock.conf IS NOT set correctly (missing or < 900)"
    fi

    # Check for non-compliant PAM override
    pam_override=$(grep -Pi -- '^\h*auth\h+(requisite|required|sufficient)\h+pam_faillock\.so\h+([^#\n\r]+\h+)?unlock_time\h*=\h*([1-9]|[1-9][0-9]|[1-8][0-9][0-9])\b' \
        /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null)

    if [ -n "$pam_override" ]; then
        l_output2+="\n - Found override:\n$pam_override"
        log_fail "unlock_time override in PAM IS set to a non-compliant value (< 900)"
    fi

    # Final output
    if [ -n "$l_output2" ]; then
        echo -e "\n - Reason(s) for audit failure:$l_output2"
    fi
    if [ -n "$l_output" ]; then
        echo -e "$l_output"
    fi
}

check_pwquality_difok_setting() {
    print_header "5.3.3.2.1 - Ensure password number of changed characters is configured"

    local l_output="" l_output2=""
    local conf_match pam_bad_override

    # Check if difok is defined with a valid value in any conf file
    conf_match=$(grep -Psi -- '^\h*difok\h*=\h*([2-9]|[1-9][0-9]+)\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null)

    if [ -n "$conf_match" ]; then
        l_output+="\n - Found setting:\n$conf_match"
        log_pass "'difok' IS set to 2 or more in pwquality configuration"
    else
        l_output2+="\n - 'difok' value not found or below minimum in pwquality.conf or .d/*.conf"
        log_fail "'difok' IS NOT set or IS less than 2 in pwquality configuration"
    fi

    # Check for bad difok override in PAM files (difok = 0 or 1)
    pam_bad_override=$(grep -Psi -- '^\h*password\h+(requisite|required|sufficient)\h+pam_pwquality\.so\h+([^#\n\r]+\h+)?difok\h*=\h*([0-1])\b' \
        /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null)

    if [ -n "$pam_bad_override" ]; then
        l_output2+="\n - Found override:\n$pam_bad_override"
        log_fail "'difok' override in PAM IS set to a NON-compliant value (< 2)"
    fi

    # Final output
    if [ -n "$l_output2" ]; then
        echo -e "\n - Reason(s) for audit failure:$l_output2"
    fi
    if [ -n "$l_output" ]; then
        echo -e "$l_output"
    fi
}

check_pwquality_minlen_setting() {
    print_header "5.3.3.2.2 - Ensure password length is configured"

    local l_output="" l_output2=""
    local conf_match pam_override

    # Check compliant minlen in pwquality configuration
    conf_match=$(grep -Psi -- '^\h*minlen\h*=\h*(1[4-9]|[2-9][0-9]|[1-9][0-9]{2,})\b' \
        /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null)

    if [ -n "$conf_match" ]; then
        l_output+="\n - Found setting:\n$conf_match"
        log_pass "'minlen' IS set to 14 or more in pwquality configuration"
    else
        l_output2+="\n - No compliant 'minlen' found in pwquality.conf or .d/*.conf"
        log_fail "'minlen' IS NOT set or IS below 14 in pwquality configuration"
    fi

    # Check for non-compliant override (minlen < 14) in PAM config
    pam_override=$(grep -Psi -- \
        '^\h*password\h+(requisite|required|sufficient)\h+pam_pwquality\.so\h+([^#\n\r]+\h+)?minlen\h*=\h*([0-9]|1[0-3])\b' \
        /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null)

    if [ -n "$pam_override" ]; then
        l_output2+="\n - Found override:\n$pam_override"
        log_fail "'minlen' override in PAM IS set to a NON-compliant value (< 14)"
    fi

    # Final output
    if [ -n "$l_output2" ]; then
        echo -e "\n - Reason(s) for audit failure:$l_output2"
    fi
    if [ -n "$l_output" ]; then
        echo -e "$l_output"
    fi
}

check_pwquality_maxrepeat_setting() {
    print_header "5.3.3.2.4 - Ensure password same consecutive characters is configured"

    local l_output="" l_output2=""
    local conf_match pam_override

    # Step 1: Check compliant maxrepeat in pwquality.conf or .d
    conf_match=$(grep -Psi -- '^\h*maxrepeat\h*=\h*[1-3]\b' \
        /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null)

    if [ -n "$conf_match" ]; then
        l_output+="\n - Found setting:\n$conf_match"
        log_pass "'maxrepeat' IS set to a compliant value (1–3)"
    else
        l_output2+="\n - Missing or invalid maxrepeat setting in pwquality.conf or .d/*.conf"
        log_fail "'maxrepeat' IS NOT set correctly (must be 1–3 and not 0)"
    fi

    # Step 2: Check for bad overrides in PAM
    pam_override=$(grep -Psi -- \
        '^\h*password\h+(requisite|required|sufficient)\h+pam_pwquality\.so\h+([^#\n\r]+\h+)?maxrepeat\h*=\h*(0|[4-9]|[1-9][0-9]+)\b' \
        /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null)

    if [ -n "$pam_override" ]; then
        l_output2+="\n - Found override:\n$pam_override"
        log_fail "'maxrepeat' IS overridden in PAM with NON-compliant value (0 or >3)"
    fi

    # Final Output
    if [ -n "$l_output2" ]; then
        echo -e "\n - Reason(s) for audit failure:$l_output2"
    fi
    if [ -n "$l_output" ]; then
        echo -e "$l_output"
    fi
}

check_pwquality_maxsequence_setting() {
    print_header "5.3.3.2.5 - Ensure password maximum sequential characters is configured"

    local l_output="" l_output2=""
    local conf_match pam_override

    # Step 1: Check compliant maxsequence in pwquality.conf or .d
    conf_match=$(grep -Psi -- '^\h*maxsequence\h*=\h*[1-3]\b' \
        /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null)

    if [ -n "$conf_match" ]; then
        l_output+="\n - Found setting:\n$conf_match"
        log_pass "'maxsequence' IS set to a compliant value (1–3)"
    else
        l_output2+="\n - Missing or invalid maxsequence setting in pwquality.conf or .d/*.conf"
        log_fail "'maxsequence' IS NOT set correctly (must be 1–3 and not 0)"
    fi

    # Step 2: Check for non-compliant PAM override (0 or >3)
    pam_override=$(grep -Psi -- \
        '^\h*password\h+(requisite|required|sufficient)\h+pam_pwquality\.so\h+([^#\n\r]+\h+)?maxsequence\h*=\h*(0|[4-9]|[1-9][0-9]+)\b' \
        /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null)

    if [ -n "$pam_override" ]; then
        l_output2+="\n - Found override:\n$pam_override"
        log_fail "'maxsequence' IS overridden in PAM with NON-compliant value (0 or >3)"
    fi

    # Final Output
    if [ -n "$l_output2" ]; then
        echo -e "\n - Reason(s) for audit failure:$l_output2"
    fi
    if [ -n "$l_output" ]; then
        echo -e "$l_output"
    fi
}

check_pwquality_dictcheck_setting() {
    print_header "5.3.3.2.6 - Ensure password dictionary check is enabled"

    local l_output="" l_output2=""
    local conf_violation pam_violation

    # Step 1: Check for dictcheck=0 in pwquality config files
    conf_violation=$(grep -Psi -- '^\h*dictcheck\h*=\h*0\b' \
        /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null)

    if [ -n "$conf_violation" ]; then
        l_output2+="\n - Found non-compliant dictcheck=0 setting:\n$conf_violation"
        log_fail "'dictcheck' IS explicitly disabled in pwquality configuration"
    else
        log_pass "'dictcheck' IS NOT disabled in pwquality configuration"
    fi

    # Step 2: Check for dictcheck=0 override in PAM
    pam_violation=$(grep -Psi -- \
        '^\h*password\h+(requisite|required|sufficient)\h+pam_pwquality\.so\h+([^#\n\r]+\h+)?dictcheck\h*=\h*0\b' \
        /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null)

    if [ -n "$pam_violation" ]; then
        l_output2+="\n - Found non-compliant override:\n$pam_violation"
        log_fail "'dictcheck' IS disabled in PAM override"
    fi

    # Final Output
    if [ -n "$l_output2" ]; then
        echo -e "\n - Reason(s) for audit failure:$l_output2"
    fi
}

check_pwquality_enforce_for_root() {
    print_header "5.3.3.2.7 - Ensure password quality is enforced for the root user"

    local l_output="" l_output2=""
    local enforce_setting

    # Check for enforce_for_root explicitly set
    enforce_setting=$(grep -Psi -- '^\h*enforce_for_root\b' \
        /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 2>/dev/null)

    if [ -n "$enforce_setting" ]; then
        l_output+="\n - Found setting:\n$enforce_setting"
        log_pass "'enforce_for_root' IS set in pwquality configuration"
    else
        l_output2+="\n - Missing 'enforce_for_root' in pwquality.conf or .d/*.conf"
        log_fail "'enforce_for_root' IS NOT set in pwquality configuration"
    fi

    # Final Output
    if [ -n "$l_output2" ]; then
        echo -e "\n - Reason(s) for audit failure:$l_output2"
    fi
    if [ -n "$l_output" ]; then
        echo -e "$l_output"
    fi
}

check_password_reuse_remember_setting() {
    print_header "5.3.3.3.1 - Ensure password history remember is configured"

    local l_output="" l_output2=""
    local conf_remember pam_override

    # Step 1: Check /etc/security/pwhistory.conf for remember >= 24
    conf_remember=$(grep -Pi -- '^\h*remember\h*=\h*(2[4-9]|[3-9][0-9]|[1-9][0-9]{2,})\b' \
        /etc/security/pwhistory.conf 2>/dev/null)

    if [ -n "$conf_remember" ]; then
        l_output+="\n - Found setting:\n$conf_remember"
        log_pass "'remember' IS set to 24 or more in /etc/security/pwhistory.conf"
    else
        l_output2+="\n - Missing or non-compliant setting in /etc/security/pwhistory.conf"
        log_fail "'remember' IS NOT set or IS less than 24 in /etc/security/pwhistory.conf"
    fi

    # Step 2: Ensure no PAM override with remember < 24
    pam_override=$(grep -Pi -- \
        '^\h*password\h+(requisite|required|sufficient)\h+pam_pwhistory\.so\h+([^#\n\r]+\h+)?remember=(2[0-3]|1[0-9]|[0-9])\b' \
        /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null)

    if [ -n "$pam_override" ]; then
        l_output2+="\n - Found override:\n$pam_override"
        log_fail "'remember' override in PAM IS set to a NON-compliant value (< 24)"
    fi

    # Final Output
    if [ -n "$l_output2" ]; then
        echo -e "\n - Reason(s) for audit failure:$l_output2"
    fi
    if [ -n "$l_output" ]; then
        echo -e "$l_output"
    fi
}

check_pwhistory_enforce_for_root() {
    print_header "5.3.3.3.2 - Ensure password history is enforced for the root user"

    local l_output="" l_output2=""
    local enforce_setting

    enforce_setting=$(grep -Pi -- '^\h*enforce_for_root\b' /etc/security/pwhistory.conf 2>/dev/null)

    if [ -n "$enforce_setting" ]; then
        l_output+="\n - Found setting:\n$enforce_setting"
        log_pass "'enforce_for_root' IS set in /etc/security/pwhistory.conf"
    else
        l_output2+="\n - Missing 'enforce_for_root' setting in pwhistory.conf"
        log_fail "'enforce_for_root' IS NOT set in /etc/security/pwhistory.conf"
    fi

    # Final output
    if [ -n "$l_output2" ]; then
        echo -e "\n - Reason(s) for audit failure:$l_output2"
    fi
    if [ -n "$l_output" ]; then
        echo -e "$l_output"
    fi
}

check_pwhistory_use_authtok() {
    print_header "5.3.3.3.3 - Ensure pam_pwhistory includes use_authtok"

    local l_output="" l_output2=""
    local result

    result=$(grep -P -- \
        '^\h*password\h+([^#\n\r]+)\h+pam_pwhistory\.so\h+([^#\n\r]+\h+)?use_authtok\b' \
        /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null)

    if [ -n "$result" ]; then
        l_output+="\n - Found setting:\n$result"
        log_pass "'use_authtok' IS set with pam_pwhistory.so in PAM password stack"
    else
        l_output2+="\n - Missing 'use_authtok' argument in PAM configuration"
        log_fail "'use_authtok' IS NOT set with pam_pwhistory.so in PAM password stack"
    fi

    # Final output
    if [ -n "$l_output2" ]; then
        echo -e "\n - Reason(s) for audit failure:$l_output2"
    fi
    if [ -n "$l_output" ]; then
        echo -e "$l_output"
    fi
}

check_pam_unix_nullok_disabled() {
    print_header "5.3.3.4.1 - Ensure pam_unix does not include nullok"

    local l_output="" l_output2=""
    local nullok_lines

    nullok_lines=$(grep -Pi -- \
        '^\h*(auth|account|password|session)\h+(requisite|required|sufficient)\h+pam_unix\.so\b.*\bnullok\b' \
        /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null)

    if [ -n "$nullok_lines" ]; then
        l_output2+="\n - Found non-compliant lines:\n$nullok_lines"
        log_fail "'nullok' IS present on pam_unix.so lines"
    else
        log_pass "'nullok' IS NOT present on pam_unix.so lines"
    fi

    # Final output
    if [ -n "$l_output2" ]; then
        echo -e "\n - Reason(s) for audit failure:$l_output2"
    fi
}

check_pam_unix_remember_not_set() {
    print_header "5.3.3.4.2 - Ensure pam_unix does not include remember"

    local l_output="" l_output2=""
    local remember_lines

    remember_lines=$(grep -Pi '^\h*password\h+([^#\n\r]+\h+)?pam_unix\.so\b.*\bremember=\d+\b' \
        /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null)

    if [ -n "$remember_lines" ]; then
        l_output2+="\n - Found incorrect 'remember' settings:\n$remember_lines"
        log_fail "'remember' IS set on pam_unix.so lines (non-compliant)"
    else
        log_pass "'remember' IS NOT set on pam_unix.so lines"
    fi

    # Final output
    if [ -n "$l_output2" ]; then
        echo -e "\n - Reason(s) for audit failure:$l_output2"
    fi
}

check_pam_unix_password_hashing() {
    print_header "5.3.3.4.3 - Ensure pam_unix includes a strong password hashing algorithm"

    local l_output="" l_output2=""
    local match_lines missing_hash

    # Find lines that contain pam_unix.so + strong hash
    match_lines=$(grep -P -- \
        '^\h*password\h+([^#\n\r]+)\h+pam_unix\.so\h+([^#\n\r]+\h+)?(sha512|yescrypt)\b' \
        /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null)

    # Check if there are any password lines using pam_unix.so without strong hash
    missing_hash=$(grep -P -- \
        '^\h*password\h+([^#\n\r]+)\h+pam_unix\.so\b(?!.*\b(sha512|yescrypt)\b)' \
        /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null)

    if [ -n "$match_lines" ] && [ -z "$missing_hash" ]; then
        l_output+="\n - Compliant lines:\n$match_lines"
        log_pass "Strong password hashing algorithm IS set on pam_unix.so (sha512 or yescrypt)"
    else
        if [ -n "$missing_hash" ]; then
            l_output2+="\n - Non-compliant lines missing 'sha512' or 'yescrypt':\n$missing_hash"
        fi
        log_fail "Strong password hashing algorithm IS NOT properly set on all pam_unix.so password lines"
    fi

    # Final Output
    if [ -n "$l_output2" ]; then
        echo -e "\n - Reason(s) for audit failure:$l_output2"
    fi
    if [ -n "$l_output" ]; then
        echo -e "$l_output"
    fi
}

check_pam_unix_use_authtok() {
    print_header "5.3.3.4.4 - Ensure pam_unix includes use_authtok"

    local l_output="" l_output2=""
    local match_lines missing_use_authtok

    # Check for correct lines that include pam_unix.so with use_authtok
    match_lines=$(grep -P -- \
        '^\h*password\h+[^#\n\r]+\h+pam_unix\.so\b.*\buse_authtok\b' \
        /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null)

    # Check for lines that use pam_unix.so but do NOT include use_authtok
    missing_use_authtok=$(grep -P -- \
        '^\h*password\h+[^#\n\r]+\h+pam_unix\.so\b(?!.*\buse_authtok\b)' \
        /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null)

    if [ -n "$match_lines" ] && [ -z "$missing_use_authtok" ]; then
        l_output+="\n - Compliant lines:\n$match_lines"
        log_pass "'use_authtok' IS set on pam_unix.so password stack lines"
    else
        if [ -n "$missing_use_authtok" ]; then
            l_output2+="\n - Non-compliant lines:\n$missing_use_authtok"
        fi
        log_fail "'use_authtok' IS NOT set on all pam_unix.so password stack lines"
    fi

    # Final Output
    if [ -n "$l_output2" ]; then
        echo -e "\n - Reason(s) for audit failure:$l_output2"
    fi
    if [ -n "$l_output" ]; then
        echo -e "$l_output"
    fi
}

check_pass_max_days() {
    print_header "5.4.1.1 - Ensure password expiration is configured"

    local l_output="" l_output2=""
    local defs_value shadow_violations

    # Check /etc/login.defs for PASS_MAX_DAYS value
    defs_value=$(grep -Pi -- '^\h*PASS_MAX_DAYS\h+\d+\b' /etc/login.defs | awk '{print $2}')

    if [[ -z "$defs_value" ]]; then
        log_fail "PASS_MAX_DAYS IS NOT set in /etc/login.defs"
        l_output2+="\n - Missing setting in /etc/login.defs"
    elif [[ "$defs_value" -le 365 && "$defs_value" -ge 1 ]]; then
        log_pass "PASS_MAX_DAYS IS set to $defs_value in /etc/login.defs"
        l_output+="\n - Found: PASS_MAX_DAYS $defs_value"
    else
        log_fail "PASS_MAX_DAYS IS set to $defs_value which is outside allowed range (1-365)"
        l_output2+="\n - Found: PASS_MAX_DAYS $defs_value"
    fi

    # Check /etc/shadow entries
    shadow_violations=$(awk -F: '($2~/^\$.+\$/) {if($5 > 365 || $5 < 1)print "User: " $1 " PASS_MAX_DAYS: " $5}' /etc/shadow)

    if [[ -z "$shadow_violations" ]]; then
        log_pass "All user PASS_MAX_DAYS values in /etc/shadow ARE within 1-365"
    else
        log_fail "Some user PASS_MAX_DAYS values in /etc/shadow ARE NOT within 1-365"
        l_output2+="\n - Non-compliant entries:\n$shadow_violations"
    fi

    # Output
    if [[ -n "$l_output" ]]; then
        echo -e "$l_output"
    fi
    if [[ -n "$l_output2" ]]; then
        echo -e "\n - Reason(s) for audit failure:$l_output2"
    fi
}

check_pass_warn_age() {
    print_header "5.4.1.3 - Ensure password expiration warning days is configured"

    local l_output="" l_output2=""
    local defs_value shadow_violations

    # Check /etc/login.defs
    defs_value=$(grep -Pi -- '^\h*PASS_WARN_AGE\h+\d+\b' /etc/login.defs | awk '{print $2}')

    if [[ -z "$defs_value" ]]; then
        log_fail "PASS_WARN_AGE IS NOT set in /etc/login.defs"
        l_output2+="\n - Missing setting in /etc/login.defs"
    elif [[ "$defs_value" -ge 7 ]]; then
        log_pass "PASS_WARN_AGE IS set to $defs_value in /etc/login.defs"
        l_output+="\n - Found: PASS_WARN_AGE $defs_value"
    else
        log_fail "PASS_WARN_AGE IS set to $defs_value which IS LESS than 7"
        l_output2+="\n - Found: PASS_WARN_AGE $defs_value"
    fi

    # Check shadow file
    shadow_violations=$(awk -F: '($2~/^\$.+\$/) {if($6 < 7)print "User: " $1 " PASS_WARN_AGE: " $6}' /etc/shadow)

    if [[ -z "$shadow_violations" ]]; then
        log_pass "All user PASS_WARN_AGE values in /etc/shadow ARE 7 or more"
    else
        log_fail "Some user PASS_WARN_AGE values in /etc/shadow ARE LESS than 7"
        l_output2+="\n - Non-compliant entries:\n$shadow_violations"
    fi

    # Output results
    if [[ -n "$l_output" ]]; then
        echo -e "$l_output"
    fi
    if [[ -n "$l_output2" ]]; then
        echo -e "\n - Reason(s) for audit failure:$l_output2"
    fi
}

check_encrypt_method() {
    print_header "5.4.1.4 - Ensure strong password hashing algorithm is configured"

    local l_output="" l_output2=""
    local method_line method

    method_line=$(grep -Pi -- '^\h*ENCRYPT_METHOD\h+\H+' /etc/login.defs)
    method=$(echo "$method_line" | awk '{print toupper($2)}')

    if [[ -z "$method" ]]; then
        log_fail "ENCRYPT_METHOD IS NOT set in /etc/login.defs"
        l_output2+="\n - Missing ENCRYPT_METHOD in /etc/login.defs"
    elif [[ "$method" == "SHA512" || "$method" == "YESCRYPT" ]]; then
        log_pass "ENCRYPT_METHOD IS set to $method"
        l_output+="\n - Found: ENCRYPT_METHOD $method"
    else
        log_fail "ENCRYPT_METHOD IS set to $method which IS NOT SHA512 or YESCRYPT"
        l_output2+="\n - Found: ENCRYPT_METHOD $method"
    fi

    # Output results
    if [[ -n "$l_output" ]]; then
        echo -e "$l_output"
    fi
    if [[ -n "$l_output2" ]]; then
        echo -e "\n - Reason(s) for audit failure:$l_output2"
    fi
}

check_password_inactive_setting() {
    print_header "5.4.1.5 - Ensure inactive password lock is configured"

    local l_output="" l_output2=""
    local inactive_default
    inactive_default=$(useradd -D | grep -Po 'INACTIVE=\K\S+')

    if [[ -z "$inactive_default" || "$inactive_default" -gt 45 || "$inactive_default" -lt 0 ]]; then
        log_fail "INACTIVE IS set to $inactive_default which IS NOT between 0 and 45"
        l_output2+="\n - Default INACTIVE: $inactive_default"
    else
        log_pass "INACTIVE IS set to $inactive_default"
        l_output+="\n - Default INACTIVE: $inactive_default"
    fi

    local shadow_violations
    shadow_violations=$(awk -F: '($2~/^\$.+\$/) {if($7 > 45 || $7 < 0)print "User: " $1 " INACTIVE: " $7}' /etc/shadow)

    if [[ -n "$shadow_violations" ]]; then
        log_fail "Some users have INACTIVE setting greater than 45 or less than 0"
        l_output2+="\n$shadow_violations"
    else
        log_pass "All users have INACTIVE setting within policy (0-45)"
    fi

    # Output results
    if [[ -n "$l_output" ]]; then
        echo -e "$l_output"
    fi
    if [[ -n "$l_output2" ]]; then
        echo -e "\n - Reason(s) for audit failure:$l_output2"
    fi
}

check_future_password_changes() {
    print_header "5.4.1.6 - Ensure all users last password change date is in the past"

    local l_output=""
    local l_user l_change

    while IFS= read -r l_user; do
        l_change=$(date -d "$(chage --list "$l_user" | grep '^Last password change' | cut -d: -f2 | grep -v 'never$')" +%s 2>/dev/null)
        if [[ -n "$l_change" && "$l_change" -gt "$(date +%s)" ]]; then
            l_output+="\n - User: \"$l_user\" has future password change: $(chage --list "$l_user" | grep '^Last password change' | cut -d: -f2)"
        fi
    done < <(awk -F: '$2~/^\$.+\$/{print $1}' /etc/shadow)

    if [[ -z "$l_output" ]]; then
        log_pass "No user accounts have password change dates in the future"
    else
        log_fail "One or more accounts HAVE password change dates in the future"
        echo -e "$l_output"
    fi
}

check_uid_0_users() {
    print_header "5.4.2.1 - Ensure root is the only UID 0 account"

    local l_output=""
    local l_uid0_users

    l_uid0_users=$(awk -F: '($3 == 0) { print $1 }' /etc/passwd)

    if [[ "$l_uid0_users" == "root" ]]; then
        log_pass "Only 'root' has UID 0"
    else
        log_fail "NOT only 'root' has UID 0"
        echo -e " - UID 0 users found:\n$(echo "$l_uid0_users" | grep -v '^root$')"
    fi
}

check_gid_0_users() {
    print_header "5.4.2.2 - Ensure root is the only GID 0 account"

    local l_output=""
    local l_gid0_users

    l_gid0_users=$(awk -F: '($1 !~ /^(sync|shutdown|halt|operator)/ && $4 == "0") {print $1 ":" $4}' /etc/passwd)

    if [[ "$l_gid0_users" == "root:0" ]]; then
        log_pass "Only 'root' has GID 0 (excluding sync/shutdown/halt/operator)"
    else
        log_fail "NOT only 'root' has GID 0"
        echo -e " - GID 0 users found:\n$l_gid0_users"
    fi
}

check_gid_0_group() {
    print_header "5.4.2.3 Ensure group root is the only GID 0 group"

    local l_output=""
    local l_gid0_groups

    l_gid0_groups=$(awk -F: '$3=="0"{print $1 ":" $3}' /etc/group)

    if [[ "$l_gid0_groups" == "root:0" ]]; then
        log_pass "Only 'root' group has GID 0"
    else
        log_fail "NOT only 'root' group has GID 0"
        echo -e " - GID 0 groups found:\n$l_gid0_groups"
    fi
}

check_root_password_or_locked() {
    print_header "5.4.2.4 - Ensure root account access is controlled"

    local l_status
    l_status=$(passwd -S root 2>/dev/null)

    if [[ "$l_status" =~ ^root\ P ]]; then
        log_pass "Root account password is set and active"
    elif [[ "$l_status" =~ ^root\ L ]]; then
        log_pass "Root account is locked"
    else
        log_fail "NOT compliant: root password is neither set nor account locked"
        echo " - passwd -S root returned: $l_status"
    fi
}

check_root_path_safety() {
    print_header "5.4.2.5 - Ensure root path integrity"

    local l_output2=""
    local l_pmask="0022"
    local l_maxperm
    l_maxperm="$( printf '%o' $(( 0777 & ~$l_pmask )) )"
    local l_root_path
    l_root_path="$(sudo -Hiu root env | grep '^PATH' | cut -d= -f2)"

    unset a_path_loc
    IFS=":" read -ra a_path_loc <<< "$l_root_path"

    # Check for empty :: entries
    grep -q "::" <<< "$l_root_path" && \
        l_output2+="\n - Root's path contains an empty directory (::)"

    # Check for trailing colon
    grep -Pq ":\h*$" <<< "$l_root_path" && \
        l_output2+="\n - Root's path contains a trailing colon (:)"

    # Check for current directory (.)
    grep -Pq '(^|:)\.(?=:|$)' <<< "$l_root_path" && \
        l_output2+="\n - Root's path contains the current working directory (.)"

    # Validate each PATH component
    for l_path in "${a_path_loc[@]}"; do
        if [ -d "$l_path" ]; then
            read -r l_fmode l_fown <<< "$(stat -Lc '%#a %U' "$l_path")"
            [ "$l_fown" != "root" ] && \
                l_output2+="\n - Directory: \"$l_path\" is owned by: \"$l_fown\"; should be owned by \"root\""
            [ $(( l_fmode & l_pmask )) -gt 0 ] && \
                l_output2+="\n - Directory: \"$l_path\" is mode: \"$l_fmode\"; should be mode: \"$l_maxperm\" or more restrictive"
        else
            l_output2+="\n - \"$l_path\" is not a valid directory"
        fi
    done

    if [ -z "$l_output2" ]; then
        log_pass "Root's PATH is correctly configured"
    else
        log_fail "NOT compliant: Issues found in root's PATH"
        echo -e "$l_output2"
    fi
}

check_root_umask() {
    print_header "5.4.2.6 - Ensure root user umask is configured"

    local files=("/root/.bash_profile" "/root/.bashrc")
    local result
    result=$(grep -Psi -- '^\h*umask\h+(([0-7][0-7][01][0-7]\b|[0-7][0-7][0-7][06]\b)|([0-7][01][0-7]\b|[0-7][0-7][06]\b)|(u=[rwx]{1,3},)?(((g=[rx]?[rx]?w[rx]?[rx]?\b)(,o=[rwx]{1,3})?)|((g=[wrx]{1,3},)?o=[wrx]{1,3}\b)))' "${files[@]}" 2>/dev/null)

    if [ -z "$result" ]; then
        log_pass "Root umask is compliant: enforces 027 or stricter (dir 750, file 640)"
    else
        log_fail "Root umask IS misconfigured or overly permissive"
        echo -e "$result"
    fi
}

check_system_account_shells() {
    print_header "5.4.2.7 - Ensure system accounts do not have a valid login shell"

    local l_valid_shells l_output
    l_valid_shells="^($(awk -F/ '$NF != "nologin" {print}' /etc/shells | sed -rn '/^\//{s,/,\\/,g;p}' | paste -s -d '|' -))$"

    l_output=$(awk -v pat="$l_valid_shells" -F: '
        ($1 !~ /^(root|halt|sync|shutdown|nfsnobody)$/ &&
        ($3 < '"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' || $3 == 65534) &&
        $7 ~ pat)
        {print "Service account: \"" $1 "\" has a valid shell: " $7}' /etc/passwd)

    if [ -z "$l_output" ]; then
        log_pass "All system accounts have non-login shells"
    else
        log_fail "One or more system accounts HAVE valid login shells"
        echo -e "$l_output"
    fi
}

check_nonroot_shell_lock_status() {
    print_header "5.4.2.8 - Ensure accounts without a valid login shell are locked"

    local l_valid_shells l_output
    l_valid_shells="^($(awk -F/ '$NF != "nologin" {print}' /etc/shells | sed -rn '/^\//{s,/,\\/,g;p}' | paste -s -d '|' -))$"

    l_output=$(
        while IFS= read -r l_user; do
            passwd -S "$l_user" 2>/dev/null | awk '$2 !~ /^L/ {print "Account: \"" $1 "\" does NOT have a valid login shell and is NOT locked"}'
        done < <(awk -v pat="$l_valid_shells" -F: '($1 != "root" && $(NF) !~ pat) {print $1}' /etc/passwd)
    )

    if [ -z "$l_output" ]; then
        log_pass "All non-root accounts without valid shells are locked"
    else
        log_fail "Some non-root accounts without valid shells are NOT locked"
        echo -e "$l_output"
    fi
}

check_tmout_configuration() {
    print_header "5.4.3.2 - Ensure default user shell timeout is configured"

    local a_output=() a_output2=() l_tmout_set="900"

    f_tmout_read_chk() {
        local l_tmout_readonly l_tmout_export
        l_tmout_readonly="$(grep -P -- '^\h*(typeset\h+xr\hTMOUT=\d+|([^#\n\r]+)?\breadonly\h+TMOUT\b)' "$l_file")"
        l_tmout_export="$(grep -P -- '^\h*(typeset\h+xr\hTMOUT=\d+|([^#\n\r]+)?\bexport\b([^#\n\r]+\b)?TMOUT\b)' "$l_file")"

        if [ -n "$l_tmout_readonly" ]; then
            a_out+=("  - Readonly is set: \"$l_tmout_readonly\" in: \"$l_file\"")
        else
            a_out2+=("  - Readonly is NOT set in: \"$l_file\"")
        fi

        if [ -n "$l_tmout_export" ]; then
            a_out+=("  - Export is set: \"$l_tmout_export\" in: \"$l_file\"")
        else
            a_out2+=("  - Export is NOT set in: \"$l_file\"")
        fi
    }

    while IFS= read -r l_file; do
        a_out=(); a_out2=()
        l_tmout_value="$(grep -Po -- '^([^#\n\r]+)?\bTMOUT=\d+\b' "$l_file" | awk -F= '{print $2}')"

        f_tmout_read_chk

        if [ -n "$l_tmout_value" ]; then
            if [[ "$l_tmout_value" -le "$l_tmout_set" && "$l_tmout_value" -gt 0 ]]; then
                a_output+=(" - TMOUT is set to: \"$l_tmout_value\" in: \"$l_file\"")
                [ "${#a_out[@]}" -gt 0 ] && a_output+=("${a_out[@]}")
            else
                a_output2+=(" - TMOUT is incorrectly set to: \"$l_tmout_value\" in: \"$l_file\"")
                [ "${#a_out[@]}" -gt 0 ] && a_output2+=("${a_out[@]}")
                [ "${#a_out2[@]}" -gt 0 ] && a_output2+=("${a_out2[@]}")
            fi
        else
            a_output2+=(" - TMOUT is NOT set in: \"$l_file\"")
            [ "${#a_out[@]}" -gt 0 ] && a_output2+=("${a_out[@]}")
            [ "${#a_out2[@]}" -gt 0 ] && a_output2+=("${a_out2[@]}")
        fi
    done < <(grep -Pls -- '^([^#\n\r]+)?\bTMOUT\b' /etc/*bashrc /etc/profile /etc/profile.d/*.sh)

    [[ ${#a_output[@]} -eq 0 && ${#a_output2[@]} -eq 0 ]] && a_output2+=(" - TMOUT is not configured")

    if [ ${#a_output2[@]} -eq 0 ]; then
        log_pass "TMOUT is correctly configured"
        printf '%s\n' "${a_output[@]}"
    else
        log_fail "TMOUT IS NOT properly configured"
        printf '%s\n' "${a_output2[@]}"
        if [ ${#a_output[@]} -gt 0 ]; then
            echo ""
            printf '%s\n' "- Partial Correct Settings:" "${a_output[@]}"
        fi
    fi
}

check_default_user_umask() {
    print_header "5.4.3.3 - Ensure default user umask is configured"

    local l_output="" l_output2="" l_output1=""

    file_umask_chk() {
        if grep -Psiq -- '^\h*umask\h+(0?[0-7][2|7]7|u(=[rwx]{0,3}),g=([rx]{0,2}),o=)(\h*#.*)?$' "$l_file"; then
            l_output="$l_output\n - umask is set correctly in \"$l_file\""
        elif grep -Psiq -- '^\h*umask\h+(([0-7]{3}\b)|([0-7]{4}\b))' "$l_file"; then
            l_output2="$l_output2\n - umask is incorrectly set in \"$l_file\""
        fi
    }

    while IFS= read -r -d $'\0' l_file; do
        file_umask_chk
    done < <(find /etc/profile.d/ -type f -name '*.sh' -print0)

    [ -z "$l_output" ] && l_file="/etc/profile" && file_umask_chk
    [ -z "$l_output" ] && l_file="/etc/bashrc" && file_umask_chk
    [ -z "$l_output" ] && l_file="/etc/bash.bashrc" && file_umask_chk

    # Check pam_umask line if above don't pass
    if [ -z "$l_output" ]; then
        l_file="/etc/pam.d/postlogin"
        if grep -Psiq -- '^\h*session\h+[^#\n\r]+\h+pam_umask\.so\h+([^#\n\r]+\h+)?umask=(0?[0-7][2|7]7)\b' "$l_file"; then
            l_output1="$l_output1\n - umask is set correctly in \"$l_file\""
        elif grep -Psiq -- '^\h*session\h+[^#\n\r]+\h+pam_umask\.so\h+([^#\n\r]+\h+)?umask=[0-7]{3,4}' "$l_file"; then
            l_output2="$l_output2\n - umask is incorrectly set in \"$l_file\""
        fi
    fi

    [ -z "$l_output" ] && l_file="/etc/login.defs" && file_umask_chk
    [ -z "$l_output" ] && l_file="/etc/default/login" && file_umask_chk

    [[ -z "$l_output" && -z "$l_output2" ]] && l_output2="$l_output2\n - umask is **NOT** set"

    if [ -z "$l_output2" ]; then
        log_pass "Default user umask is correctly configured"
        echo -e "$l_output\n$l_output1"
    else
        log_fail "Default user umask IS NOT correctly configured"
        echo -e "$l_output2"
        [ -n "$l_output" ] && echo -e "\n- * Correctly configured *:\n$l_output\n"
    fi
}

check_aide_scheduled() {
    print_header "6.1.2 - Ensure filesystem integrity is regularly checked"

    local l_cron_aide
    local l_service_enabled l_timer_enabled l_timer_active

    l_cron_aide=$(grep -Ers '^([^#]+\s+)?(\/usr\/s?bin\/|^\s*)aide(\.wrapper)?\s(--?\S+\s)*(--(check|update)|\$AIDEARGS)\b' /etc/cron.* /etc/crontab /var/spool/cron/ 2>/dev/null)

    l_service_enabled=$(systemctl is-enabled aidecheck.service 2>/dev/null)
    l_timer_enabled=$(systemctl is-enabled aidecheck.timer 2>/dev/null)
    l_timer_active=$(systemctl is-active aidecheck.timer 2>/dev/null)

    if [[ -n "$l_cron_aide" ]]; then
        log_pass "AIDE check is scheduled via cron"
        echo -e "$l_cron_aide"
    elif [[ "$l_service_enabled" == "enabled" && "$l_timer_enabled" == "enabled" && "$l_timer_active" == "active" ]]; then
        log_pass "AIDE check is scheduled via systemd timer"
        echo -e "aidecheck.service: $l_service_enabled\naidecheck.timer: $l_timer_enabled ($l_timer_active)"
    else
        log_fail "AIDE check IS NOT properly scheduled"
        echo -e "Cron entries: ${l_cron_aide:-None Found}"
        echo -e "Systemd status:\n - aidecheck.service: $l_service_enabled\n - aidecheck.timer: $l_timer_enabled ($l_timer_active)"
    fi
}

check_aide_audit_tool_integrity() {
  print_header "6.1.3 - Ensure cryptographic mechanisms are used to protect the integrity of audit tools"

  local l_systemd_analyze
  l_systemd_analyze="$(command -v systemd-analyze)"
  if [[ -z "$l_systemd_analyze" ]]; then
    log_fail "systemd-analyze command NOT found"
    return
  fi

  local aide_conf
  aide_conf="$(command -v aide.conf || find /etc -name aide.conf 2>/dev/null | head -n1)"
  if [[ ! -f "$aide_conf" ]]; then
    log_fail "AIDE configuration file NOT found"
    return
  fi

  local -a audit_tools=(auditctl auditd ausearch aureport autrace augenrules)
  local -a required_flags=(p i n u g s b acl xattrs sha512)
  local -A tool_to_file=()
  local has_fail=0

  # Build a map of audit tool definitions in aide.conf
  while IFS= read -r line; do
    if [[ "$line" =~ ^\s*#\s*/.+\.conf$ ]]; then
      current_file="${line//# /}"
    else
      for tool in "${audit_tools[@]}"; do
        if [[ "$line" =~ (^|\s)/usr/s?bin/$tool(\.wrapper)? ]]; then
          tool_to_file["$tool"]+="$line||$current_file"$'\n'
        fi
      done
    fi
  done < <("$l_systemd_analyze" cat-config "$aide_conf" 2>/dev/null)

  for tool in "${audit_tools[@]}"; do
    if [[ -n "${tool_to_file[$tool]}" ]]; then
      while IFS= read -r entry; do
        IFS='||' read -r config_line source_file <<< "$entry"
        local missing_flags=()
        for flag in "${required_flags[@]}"; do
          grep -qP "\b${flag}\b" <<< "$config_line" || missing_flags+=("$flag")
        done
        if [[ ${#missing_flags[@]} -eq 0 ]]; then
          log_pass "AIDE monitors '$tool' with all required flags in $source_file"
        else
          has_fail=1
          log_fail "'$tool' in $source_file is missing: ${missing_flags[*]}"
        fi

        # Warn if tool is referenced by symlink instead of real path
        local config_path
        config_path=$(awk '{print $1}' <<< "$config_line")
        local real_path
        real_path=$(readlink -f "$config_path")
        if [[ "$config_path" != "$real_path" ]]; then
          log_warn "'$tool' is referenced as '$config_path' (should be '$real_path')"
        fi
      done <<< "${tool_to_file[$tool]}"
    else
      has_fail=1
      log_fail "AIDE configuration IS missing entry for '$tool'"
    fi
  done

  if [[ "$has_fail" -eq 0 ]]; then
    log_pass "AIDE is properly monitoring all required audit tools with correct options"
  fi
}

check_systemd_journald_status() {
  print_header "6.2.1.1 - Ensure journald service is enabled and active"

  local is_enabled is_active

  is_enabled=$(systemctl is-enabled systemd-journald.service 2>/dev/null)
  is_active=$(systemctl is-active systemd-journald.service 2>/dev/null)

  if [[ "$is_enabled" == "static" ]]; then
    log_pass "systemd-journald.service is statically enabled (expected behavior)"
  else
    log_fail "systemd-journald.service is NOT static (value: $is_enabled); investigate"
  fi

  if [[ "$is_active" == "active" ]]; then
    log_pass "systemd-journald.service is active"
  else
    log_fail "systemd-journald.service is NOT active (value: $is_active)"
  fi
}

check_single_logging_system() {
  print_header "6.2.1.4 - Ensure only one logging system is in use"

  local log_used=""
  local log_error=""

  if systemctl is-active --quiet rsyslog; then
    log_pass "rsyslog is active — follow rsyslog configuration guidance"
  elif systemctl is-active --quiet systemd-journald; then
    log_pass "systemd-journald is active — follow journald configuration guidance"
  else
    log_fail "Unable to determine system logging. Neither rsyslog nor journald is active"
  fi
}

detect_logging_method() {
    if systemctl is-active --quiet rsyslog; then
        LOGGING_METHOD="rsyslog"
        log_pass "Logging method detected: rsyslog is active. Use rsyslog-specific checks."
    elif systemctl is-active --quiet systemd-journald; then
        LOGGING_METHOD="journald"
        log_pass "Logging method detected: journald is active. Use journald-specific checks."
    else
        LOGGING_METHOD="unknown"
        log_fail "Unable to determine logging method. Neither rsyslog nor journald appears active."
    fi
}

audit_systemd_journal_upload() {
    print_header "6.2.2.1.3 - Ensure systemd-journal-upload is enabled and active"
    detect_logging_method

    if [[ "$LOGGING_METHOD" != "journald" ]]; then
        log_pass "Skipping systemd-journal-upload check: journald is not the active logging method."
        return
    fi

    if ! systemctl list-unit-files | grep -q '^systemd-journal-upload.service'; then
        log_fail "systemd-journal-upload.service DOES NOT exist on system"
        return
    fi

    local enabled_status
    enabled_status=$(systemctl is-enabled systemd-journal-upload.service 2>/dev/null)

    local active_status
    active_status=$(systemctl is-active systemd-journal-upload.service 2>/dev/null)

    if [[ "$enabled_status" == "enabled" && "$active_status" == "active" ]]; then
        log_pass "systemd-journal-upload.service IS enabled and active"
    else
        [[ "$enabled_status" != "enabled" ]] && log_fail "systemd-journal-upload.service IS NOT enabled (status: $enabled_status)"
        [[ "$active_status" != "active" ]] && log_fail "systemd-journal-upload.service IS NOT active (status: $active_status)"
    fi
}

audit_systemd_journal_remote_disabled() {
    print_header "6.2.2.1.4 - Ensure systemd-journal-remote service is not in use"
    detect_logging_method

    if [[ "$LOGGING_METHOD" != "journald" ]]; then
        log_pass "Skipping systemd-journal-remote check: journald is not the active logging method."
        return
    fi

    local units=("systemd-journal-remote.socket" "systemd-journal-remote.service")
    local fail=0

    for unit in "${units[@]}"; do
        if systemctl list-unit-files | grep -q "^$unit"; then
            local enabled_status
            enabled_status=$(systemctl is-enabled "$unit" 2>/dev/null)
            if [[ "$enabled_status" == "enabled" ]]; then
                log_fail "$unit IS enabled"
                fail=1
            fi

            local active_status
            active_status=$(systemctl is-active "$unit" 2>/dev/null)
            if [[ "$active_status" == "active" ]]; then
                log_fail "$unit IS active"
                fail=1
            fi
        else
            log_pass "$unit does not exist on system"
        fi
    done

    if [[ $fail -eq 0 ]]; then
        log_pass "systemd-journal-remote.socket and systemd-journal-remote.service are NOT enabled or active"
    fi
}

audit_journald_forward_to_syslog() {
    print_header "6.2.2.2 - Ensure journald ForwardToSyslog is disabled"
    detect_logging_method

    if [[ "$LOGGING_METHOD" != "journald" ]]; then
        log_pass "Skipping ForwardToSyslog check: journald is not the active logging method."
        return
    fi

    if systemd-analyze cat-config systemd/journald.conf systemd/journald.conf.d/* 2>/dev/null | grep -qE "^ForwardToSyslog=no"; then
        log_pass "ForwardToSyslog IS set to no"
    else
        log_fail "ForwardToSyslog is NOT set to no"
    fi
}

audit_journald_compress_yes() {
    print_header "6.2.2.3 - Ensure journald Compress is configured"
    detect_logging_method

    if [[ "$LOGGING_METHOD" != "journald" ]]; then
        log_pass "Skipping Compress check: journald is not the active logging method."
        return
    fi

    if systemd-analyze cat-config systemd/journald.conf systemd/journald.conf.d/* 2>/dev/null | grep -qE "^Compress=yes"; then
        log_pass "Compress IS set to yes"
    else
        log_fail "Compress is NOT set to yes"
    fi
}

audit_journald_storage_persistent() {
    print_header "6.2.2.4 - Ensure journald Storage is configured"
    detect_logging_method

    if [[ "$LOGGING_METHOD" != "journald" ]]; then
        log_pass "Skipping Storage check: journald is not the active logging method."
        return
    fi

    if systemd-analyze cat-config systemd/journald.conf systemd/journald.conf.d/* 2>/dev/null | grep -qE "^Storage=persistent"; then
        log_pass "Storage IS set to persistent"
    else
        log_fail "Storage is NOT set to persistent"
    fi
}

audit_rsyslog_service_status() {
    print_header "6.2.3.2 - Ensure rsyslog service is enabled and active"

    detect_logging_method

    if [[ "$LOGGING_METHOD" != "rsyslog" ]]; then
        log_pass "Skipping rsyslog check: journald is the active logging method."
        return
    fi

    l_enabled_status="$(systemctl is-enabled rsyslog 2>/dev/null)"
    l_active_status="$(systemctl is-active rsyslog.service 2>/dev/null)"

    if [[ "$l_enabled_status" == "enabled" && "$l_active_status" == "active" ]]; then
        log_pass "rsyslog.service is ENABLED and ACTIVE"
    else
        [[ "$l_enabled_status" != "enabled" ]] && log_fail "rsyslog.service IS NOT enabled"
        [[ "$l_active_status" != "active" ]] && log_fail "rsyslog.service IS NOT active"
    fi
}

audit_journald_forward_to_rsyslog() {
    print_header "6.2.3.3 - Ensure journald is configured to send logs to rsyslog"

    detect_logging_method

    if [[ "$LOGGING_METHOD" != "rsyslog" ]]; then
        log_pass "Skipping ForwardToSyslog check: journald is the active logging method."
        return
    fi

    if systemd-analyze cat-config systemd/journald.conf systemd/journald.conf.d/* 2>/dev/null | grep -qE "^ForwardToSyslog=yes"; then
        log_pass "ForwardToSyslog=yes is set in journald config"
    else
        log_fail "ForwardToSyslog IS NOT set to 'yes' in journald config"
    fi
}

audit_rsyslog_file_create_mode() {
    print_header "6.2.3.4 -Ensure rsyslog log file creation mode is configured"

    detect_logging_method

    if [[ "$LOGGING_METHOD" != "rsyslog" ]]; then
        log_pass "Skipping \$FileCreateMode check: journald is the active logging method."
        return
    fi

    if grep -Psq '^\h*\$FileCreateMode\h+0[0,2,4,6][0,2,4]0\b' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null; then
        log_pass "\$FileCreateMode is correctly set in rsyslog configuration"
    else
        log_fail "\$FileCreateMode IS NOT set to 0640 or more restrictive in rsyslog configuration"
    fi
}

audit_rsyslog_no_remote_logs() {
    print_header "6.2.3.7 - Ensure rsyslog is not configured to receive logs from a remote client"

    detect_logging_method

    if [[ "$LOGGING_METHOD" != "rsyslog" ]]; then
        log_pass "Skipping rsyslog remote logging check: journald is the active logging method."
        return
    fi

    l_files="/etc/rsyslog.conf /etc/rsyslog.d/*.conf"
    l_fail=0

    # Advanced format checks
    if grep -Psiq -- '^\h*module\(load=\"?imtcp\"?\)' $l_files 2>/dev/null; then
        log_fail "Advanced rsyslog config ENABLES TCP listener via module(load=\"imtcp\")"
        l_fail=1
    fi
    if grep -Psiq -- '^\h*input\(type=\"?imtcp\"?' $l_files 2>/dev/null; then
        log_fail "Advanced rsyslog config ENABLES TCP input via input(type=\"imtcp\")"
        l_fail=1
    fi

    # Obsolete legacy format checks
    if grep -Psiq -- '^\h*\$ModLoad\h+imtcp\b' $l_files 2>/dev/null; then
        log_fail "Legacy rsyslog config LOADS imtcp module via \$ModLoad imtcp"
        l_fail=1
    fi
    if grep -Psiq -- '^\h*\$InputTCPServerRun\b' $l_files 2>/dev/null; then
        log_fail "Legacy rsyslog config ENABLES TCP server via \$InputTCPServerRun"
        l_fail=1
    fi

    if [[ "$l_fail" -eq 0 ]]; then
        log_pass "rsyslog is NOT configured to accept incoming logs"
    fi
}

audit_var_log_permissions() {
    print_header "6.2.4.1 - Ensure access to all logfiles has been configured"

    l_output2=""
    l_uidmin="$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"

    file_test_chk() {
        l_op2=""
        if [ $((l_mode & perm_mask)) -gt 0 ]; then
            l_op2="$l_op2\n  - Mode: \"$l_mode\" should be \"$maxperm\" or more restrictive"
        fi
        if [[ ! "$l_user" =~ $l_auser ]]; then
            l_op2="$l_op2\n  - Owned by: \"$l_user\" and should be owned by \"${l_auser//|/ or }\""
        fi
        if [[ ! "$l_group" =~ $l_agroup ]]; then
            l_op2="$l_op2\n  - Group owned by: \"$l_group\" and should be group owned by \"${l_agroup//|/ or }\""
        fi
        [ -n "$l_op2" ] && l_output2="$l_output2\n - File: \"$l_fname\" is:$l_op2\n"
    }

    unset a_file
    a_file=()

    while IFS= read -r -d $'\0' l_file; do
        [ -e "$l_file" ] && a_file+=("$(stat -Lc '%n^%#a^%U^%u^%G^%g' "$l_file")")
    done < <(find -L /var/log -type f \( -perm /0137 -o ! -user root -o ! -group root \) -print0)

    while IFS="^" read -r l_fname l_mode l_user l_uid l_group l_gid; do
        l_bname="$(basename "$l_fname")"
        case "$l_bname" in
            lastlog | lastlog.* | wtmp | wtmp.* | wtmp-* | btmp | btmp.* | btmp-* | README)
                perm_mask=0113
                maxperm="$(printf '%o' $((0777 & ~perm_mask)))"
                l_auser="root"
                l_agroup="(root|utmp)"
                ;;
            secure | auth.log | syslog | messages)
                perm_mask=0137
                maxperm="$(printf '%o' $((0777 & ~perm_mask)))"
                l_auser="(root|syslog)"
                l_agroup="(root|adm)"
                ;;
            SSSD | sssd)
                perm_mask=0117
                maxperm="$(printf '%o' $((0777 & ~perm_mask)))"
                l_auser="(root|SSSD)"
                l_agroup="(root|SSSD)"
                ;;
            gdm | gdm3)
                perm_mask=0117
                maxperm="$(printf '%o' $((0777 & ~perm_mask)))"
                l_auser="root"
                l_agroup="(root|gdm|gdm3)"
                ;;
            *.journal | *.journal~)
                perm_mask=0137
                maxperm="$(printf '%o' $((0777 & ~perm_mask)))"
                l_auser="root"
                l_agroup="(root|systemd-journal)"
                ;;
            *)
                perm_mask=0137
                maxperm="$(printf '%o' $((0777 & ~perm_mask)))"
                l_auser="(root|syslog)"
                l_agroup="(root|adm)"
                if [ "$l_uid" -lt "$l_uidmin" ] && [ -z "$(awk -v grp="$l_group" -F: '$1==grp {print $4}' /etc/group)" ]; then
                    [[ ! "$l_user" =~ $l_auser ]] && l_auser="(root|syslog|$l_user)"
                    if [[ ! "$l_group" =~ $l_agroup ]]; then
                        l_tst=""
                        while read -r l_duid; do
                            [ "$l_duid" -ge "$l_uidmin" ] && l_tst=failed
                        done <<< "$(awk -F: '$4=='"$l_gid"' {print $3}' /etc/passwd)"
                        [ "$l_tst" != "failed" ] && l_agroup="(root|adm|$l_group)"
                    fi
                fi
                ;;
        esac
        file_test_chk
    done <<< "$(printf '%s\n' "${a_file[@]}")"

    unset a_file

    if [ -z "$l_output2" ]; then
        log_pass "All files in /var/log/ have appropriate permissions and ownership"
    else
        log_fail "Some files in /var/log/ have incorrect permissions or ownership"
        echo -e "$l_output2"
    fi
} 

audit_file_perms_ownership() {
    local file_path="$1"
    local expected_mode="$2"
    local expected_uid="$3"
    local expected_gid="$4"

    print_header "7.1.1 Ensure permissions on $file_path are configured"

    if [ ! -e "$file_path" ]; then
        log_fail "$file_path DOES NOT exist"
        return
    fi

    local stat_output actual_mode actual_uid actual_gid
    stat_output=$(stat -Lc '%a %u %g %U %G' "$file_path")
    actual_mode=$(awk '{print $1}' <<< "$stat_output")
    actual_uid=$(awk '{print $2}' <<< "$stat_output")
    actual_gid=$(awk '{print $3}' <<< "$stat_output")
    actual_uid_name=$(awk '{print $4}' <<< "$stat_output")
    actual_gid_name=$(awk '{print $5}' <<< "$stat_output")

    # Convert expected user/group to numeric if needed
    if ! [[ "$expected_uid" =~ ^[0-9]+$ ]]; then
        expected_uid=$(id -u "$expected_uid" 2>/dev/null)
    fi
    if ! [[ "$expected_gid" =~ ^[0-9]+$ ]]; then
        expected_gid=$(getent group "$expected_gid" | cut -d: -f3)
    fi

    if [[ "$actual_mode" -le "$expected_mode" && "$actual_uid" -eq "$expected_uid" && "$actual_gid" -eq "$expected_gid" ]]; then
        log_pass "$file_path permissions are $actual_mode and owned by $actual_uid_name:$actual_gid_name"
    else
        log_fail "$file_path HAS incorrect settings - Mode: $actual_mode (expected: $expected_mode), UID: $actual_uid_name/$actual_uid (expected: $expected_uid), GID: $actual_gid_name/$actual_gid (expected: $expected_gid)"
    fi
}

check_world_writable_files_and_dirs() {
    print_header "7.1.11 - Ensure world writable files and directories are secured"

    local l_output="" l_output2=""
    local l_smask='01000'
    local -a a_file=()
    local -a a_dir=()
    local -a a_path=(! -path "/run/user/*" -a ! -path "/proc/*" -a ! -path "*/containerd/*" -a ! -path "*/kubelet/pods/*" -a ! -path "*/kubelet/plugins/*" -a ! -path "/sys/*" -a ! -path "/snap/*")

    while IFS= read -r l_mount; do
        while IFS= read -r -d $'\0' l_file; do
            if [ -e "$l_file" ]; then
                [ -f "$l_file" ] && a_file+=("$l_file")
                if [ -d "$l_file" ]; then
                    local l_mode
                    l_mode="$(stat -Lc '%#a' "$l_file")"
                    [ ! $(( l_mode & l_smask )) -gt 0 ] && a_dir+=("$l_file")
                fi
            fi
        done < <(find "$l_mount" -xdev \( "${a_path[@]}" \) \( -type f -o -type d \) -perm -0002 -print0 2>/dev/null)
    done < <(findmnt -Dkerno fstype,target | awk '($1 !~ /^\s*(nfs|proc|smb|vfat|iso9660|efivarfs|selinuxfs)/ && $2 !~ /^(\/run\/user\/|\/tmp|\/var\/tmp)/){print $2}')

    if [ ${#a_file[@]} -eq 0 ]; then
        l_output+="\n  - No world-writable files exist on the local filesystem."
    else
        l_output2+="\n - Found ${#a_file[@]} world-writable files:\n$(printf '%s\n' "${a_file[@]}")\n"
    fi

    if [ ${#a_dir[@]} -eq 0 ]; then
        l_output+="\n  - Sticky bit is set on all world-writable directories."
    else
        l_output2+="\n - Found ${#a_dir[@]} world-writable directories **without** sticky bit:\n$(printf '%s\n' "${a_dir[@]}")\n"
    fi

    # Report results
    if [ -z "$l_output2" ]; then
        log_pass "No world-writable files or directories without sticky bit found"
        printf "%b\n" "$l_output"
    else
        log_fail "World-writable items FOUND without sticky bit or incorrect configuration"
        printf "%b\n" "$l_output2"
        [ -n "$l_output" ] && printf "%b\n" "$l_output"
    fi
}

check_nouser_nogroup_files() {
    print_header "7.1.12 - Ensure no files or directories without an owner and a group exist"

    local l_output="" l_output2=""
    local -a a_nouser=()
    local -a a_nogroup=()
    local -a a_path=(! -path "/run/user/*" -a ! -path "/proc/*" -a ! -path "*/containerd/*" -a ! -path "*/kubelet/pods/*" -a ! -path "*/kubelet/plugins/*" -a ! -path "/sys/fs/cgroup/memory/*" -a ! -path "/var/*/private/*")

    while IFS= read -r l_mount; do
        while IFS= read -r -d $'\0' l_file; do
            if [ -e "$l_file" ]; then
                while IFS=: read -r l_user l_group; do
                    [ "$l_user" = "UNKNOWN" ] && a_nouser+=("$l_file")
                    [ "$l_group" = "UNKNOWN" ] && a_nogroup+=("$l_file")
                done < <(stat -Lc '%U:%G' "$l_file")
            fi
        done < <(find "$l_mount" -xdev \( "${a_path[@]}" \) \( -type f -o -type d \) \( -nouser -o -nogroup \) -print0 2>/dev/null)
    done < <(findmnt -Dkerno fstype,target | awk '($1 !~ /^\s*(nfs|proc|smb|vfat|iso9660|efivarfs|selinuxfs)/ && $2 !~ /^\/run\/user\//){print $2}')

    if [ ${#a_nouser[@]} -eq 0 ]; then
        l_output+="\n  - No files or directories without an owner exist on the local filesystem."
    else
        l_output2+="\n  - Found ${#a_nouser[@]} unowned files/directories:\n$(printf '%s\n' "${a_nouser[@]}")\n"
    fi

    if [ ${#a_nogroup[@]} -eq 0 ]; then
        l_output+="\n  - No files or directories without a group exist on the local filesystem."
    else
        l_output2+="\n  - Found ${#a_nogroup[@]} ungrouped files/directories:\n$(printf '%s\n' "${a_nogroup[@]}")\n"
    fi

    unset a_path a_nouser a_nogroup

    if [ -z "$l_output2" ]; then
        log_pass "No unowned or ungrouped files or directories found"
        printf "%b\n" "$l_output"
    else
        log_fail "Unowned or ungrouped files/directories WERE found"
        printf "%b\n" "$l_output2"
        [ -n "$l_output" ] && printf "%b\n" "$l_output"
    fi
}

check_shadowed_passwords() {
    print_header "7.2.1 - Ensure accounts in /etc/passwd use shadowed passwords"

    local l_output="" l_output2=""
    local results
    results=$(awk -F: '($2 != "x" ) { print "User: \"" $1 "\" is not set to shadowed passwords" }' /etc/passwd)

    if [ -z "$results" ]; then
        log_pass "All users have shadowed passwords (field 2 is 'x')"
    else
        log_fail "Some users are NOT set to use shadowed passwords"
        l_output2="$results"
        printf "%b\n" "$l_output2"
    fi
}

check_users_have_passwords() {
    print_header "7.2.2 - Ensure /etc/shadow password fields are not empty"

    local l_output=""
    local results
    results=$(awk -F: '($2 == "" ) { print "User: \"" $1 "\" does not have a password" }' /etc/shadow)

    if [ -z "$results" ]; then
        log_pass "All users in /etc/shadow have passwords set"
    else
        log_fail "Some users in /etc/shadow DO NOT have passwords set"
        printf "%b\n" "$results"
    fi
}

check_gids_exist_in_group() {
    print_header "7.2.3 - Ensure all groups in /etc/passwd exist in /etc/group"

    local l_output=""
    local l_output2=""

    # Collect all GIDs from /etc/passwd
    mapfile -t a_passwd_group_gid < <(awk -F: '{print $4}' /etc/passwd | sort -u)
    # Collect all GIDs from /etc/group
    mapfile -t a_group_gid < <(awk -F: '{print $3}' /etc/group | sort -u)

    # Identify GIDs in /etc/passwd not found in /etc/group
    for gid in "${a_passwd_group_gid[@]}"; do
        if ! printf '%s\n' "${a_group_gid[@]}" | grep -qx "$gid"; then
            awk -F: -v gid="$gid" '$4 == gid {print "  - User: \"" $1 "\" has GID: \"" gid "\" which does NOT exist in /etc/group"}' /etc/passwd >> >(l_output2+=$(cat); echo)
        fi
    done

    if [ -z "$l_output2" ]; then
        log_pass "All GIDs in /etc/passwd exist in /etc/group"
    else
        log_fail "Some GIDs in /etc/passwd DO NOT exist in /etc/group"
        printf "%b\n" "$l_output2"
    fi

    # Cleanup
    unset a_passwd_group_gid a_group_gid
}

check_duplicate_uids() {
    print_header "7.2.4 - Ensure no duplicate UIDs exist"

    local l_output=""
    local l_output2=""

    while read -r l_count l_uid; do
        if [ "$l_count" -gt 1 ]; then
            local users
            users=$(awk -F: -v n="$l_uid" '($3 == n) { print $1 }' /etc/passwd | xargs)
            l_output2+=$'\n'"Duplicate UID: \"$l_uid\" Users: \"$users\""
        fi
    done < <(cut -f3 -d":" /etc/passwd | sort -n | uniq -c)

    if [ -z "$l_output2" ]; then
        log_pass "No duplicate UIDs found in /etc/passwd"
    else
        log_fail "Duplicate UIDs FOUND in /etc/passwd"
        printf "%b\n" "$l_output2"
    fi
}

check_duplicate_gids() {
    print_header "7.2.5 - Ensure no duplicate GIDs exist"

    local l_output2=""

    while read -r l_count l_gid; do
        if [ "$l_count" -gt 1 ]; then
            local groups
            groups=$(awk -F: -v n="$l_gid" '($3 == n) { print $1 }' /etc/group | xargs)
            l_output2+=$'\n'"Duplicate GID: \"$l_gid\" Groups: \"$groups\""
        fi
    done < <(cut -f3 -d":" /etc/group | sort -n | uniq -c)

    if [ -z "$l_output2" ]; then
        log_pass "No duplicate GIDs found in /etc/group"
    else
        log_fail "Duplicate GIDs FOUND in /etc/group"
        printf "%b\n" "$l_output2"
    fi
}

check_duplicate_usernames() {
    print_header "7.2.6 - Ensure no duplicate user names exist"

    local l_output2=""

    while read -r l_count l_user; do
        if [ "$l_count" -gt 1 ]; then
            local matches
            matches=$(awk -F: -v n="$l_user" '($1 == n) { print $1 }' /etc/passwd | xargs)
            l_output2+=$'\n'"Duplicate Username: \"$l_user\" Users: \"$matches\""
        fi
    done < <(cut -f1 -d":" /etc/passwd | sort | uniq -c)

    if [ -z "$l_output2" ]; then
        log_pass "No duplicate usernames found in /etc/passwd"
    else
        log_fail "Duplicate usernames FOUND in /etc/passwd"
        printf "%b\n" "$l_output2"
    fi
}

check_duplicate_groupnames() {
    print_header "7.2.7 - Ensure no duplicate group names exist"

    local l_output2=""

    while read -r l_count l_group; do
        if [ "$l_count" -gt 1 ]; then
            local matches
            matches=$(awk -F: -v n="$l_group" '($1 == n) { print $1 }' /etc/group | xargs)
            l_output2+=$'\n'"Duplicate Group: \"$l_group\" Groups: \"$matches\""
        fi
    done < <(cut -f1 -d":" /etc/group | sort | uniq -c)

    if [ -z "$l_output2" ]; then
        log_pass "No duplicate group names found in /etc/group"
    else
        log_fail "Duplicate group names FOUND in /etc/group"
        printf "%b\n" "$l_output2"
    fi
}

check_local_user_home_dirs() {
    print_header "7.2.8 - Ensure local interactive user home directories are configured "

    local l_output="" l_output2=""
    local l_heout2="" l_hoout2="" l_haout2=""
    local l_mask='0027'
    local l_max
    l_max="$(printf '%o' $((0777 & ~l_mask)))"

    local l_valid_shells
    l_valid_shells="^($(awk -F\/ '$NF != "nologin" {print}' /etc/shells | sed -rn '/^\//{s,/,\\\\/,g;p}' | paste -s -d '|' - ))$"

    unset a_uarr && a_uarr=()

    while read -r l_epu l_eph; do
        a_uarr+=("$l_epu $l_eph")
    done <<< "$(awk -v pat="$l_valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }' /etc/passwd)"

    [ "${#a_uarr[@]}" -gt 10000 ] && echo -e "\n  ** INFO **\n  - \"${#a_uarr[@]}\" Local interactive users found on the system\n  - This may be a long running check\n"

    while read -r l_user l_home; do
        if [ -d "$l_home" ]; then
            while read -r l_own l_mode; do
                [[ "$l_user" != "$l_own" ]] && l_hoout2+=$'\n'"  - User: \"$l_user\" Home \"$l_home\" is owned by: \"$l_own\""
                if [ $((l_mode & l_mask)) -gt 0 ]; then
                    l_haout2+=$'\n'"  - User: \"$l_user\" Home \"$l_home\" is mode: \"$l_mode\" should be mode: \"$l_max\" or more restrictive"
                fi
            done <<< "$(stat -Lc '%U %#a' "$l_home")"
        else
            l_heout2+=$'\n'"  - User: \"$l_user\" Home \"$l_home\" doesn't exist"
        fi
    done <<< "$(printf '%s\n' "${a_uarr[@]}")"

    [ -z "$l_heout2" ] && l_output+=$'\n'"   - home directories exist" || l_output2+="$l_heout2"
    [ -z "$l_hoout2" ] && l_output+=$'\n'"   - own their home directory" || l_output2+="$l_hoout2"
    [ -z "$l_haout2" ] && l_output+=$'\n'"   - home directories are mode: \"$l_max\" or more restrictive" || l_output2+="$l_haout2"

    [ -n "$l_output" ] && l_output="  - All local interactive users:$l_output"

    if [ -z "$l_output2" ]; then
        log_pass "All local interactive user home directories are secure"
        printf "%b\n" "$l_output"
    else
        log_fail "Some local interactive user home directories ARE misconfigured"
        printf "%b\n" "$l_output2"
        [ -n "$l_output" ] && printf "\n- * Correctly configured * :\n%b\n" "$l_output"
    fi
}

check_user_dot_files() {
    print_header "7.2.9 - Ensure local interactive user dot files access is configured"

    a_output2=(); a_output3=()
    l_maxsize="1000"
    l_valid_shells="^($(awk -F\/ '$NF != "nologin" {print}' /etc/shells | sed -rn '/^\//{s,/,\\\\/,g;p}' | paste -s -d '|' - ))$"
    a_user_and_home=()

    while read -r l_local_user l_local_user_home; do
        [[ -n "$l_local_user" && -n "$l_local_user_home" ]] && a_user_and_home+=("$l_local_user:$l_local_user_home")
    done <<< "$(awk -v pat="$l_valid_shells" -F: '$(NF) ~ pat { print $1 " " $(NF-1) }' /etc/passwd)"

    l_asize="${#a_user_and_home[@]}"
    [ "$l_asize" -gt "$l_maxsize" ] && echo -e "\n  ** INFO **\n  - \"$l_asize\" Local interactive users found on the system\n  - This may be a long running check\n"

    file_access_chk() {
        a_access_out=()
        l_max="$(printf '%o' $((0777 & ~$l_mask)))"
        if [ $((l_mode & l_mask)) -gt 0 ]; then
            a_access_out+=("  - File: \"$l_hdfile\" is mode: \"$l_mode\" and should be mode: \"$l_max\" or more restrictive")
        fi
        if [[ ! "$l_owner" =~ ($l_user) ]]; then
            a_access_out+=("  - File: \"$l_hdfile\" owned by: \"$l_owner\" and should be owned by \"$l_user\"")
        fi
        if [[ ! "$l_gowner" =~ ($l_group) ]]; then
            a_access_out+=("  - File: \"$l_hdfile\" group owned by: \"$l_gowner\" and should be group owned by \"$l_group\"")
        fi
    }

    while IFS=: read -r l_user l_home; do
        a_dot_file=(); a_netrc=(); a_netrc_warn=(); a_bhout=(); a_hdirout=()
        if [ -d "$l_home" ]; then
            l_group="$(id -gn "$l_user" | xargs)"
            l_group="${l_group// /|}"

            while IFS= read -r -d $'\0' l_hdfile; do
                while read -r l_mode l_owner l_gowner; do
                    case "$(basename "$l_hdfile")" in
                        .forward | .rhost)
                            a_dot_file+=("  - File: \"$l_hdfile\" exists") ;;
                        .netrc)
                            l_mask='0177'
                            file_access_chk
                            if [ "${#a_access_out[@]}" -gt 0 ]; then
                                a_netrc+=("${a_access_out[@]}")
                            else
                                a_netrc_warn+=("   - File: \"$l_hdfile\" exists (warning: allowed by policy)")
                            fi ;;
                        .bash_history)
                            l_mask='0177'
                            file_access_chk
                            [ "${#a_access_out[@]}" -gt 0 ] && a_bhout+=("${a_access_out[@]}") ;;
                        *)
                            l_mask='0133'
                            file_access_chk
                            [ "${#a_access_out[@]}" -gt 0 ] && a_hdirout+=("${a_access_out[@]}") ;;
                    esac
                done < <(stat -Lc '%#a %U %G' "$l_hdfile")
            done < <(find "$l_home" -xdev -type f -name '.*' -print0)
        fi

        if [[ "${#a_dot_file[@]}" -gt 0 || "${#a_netrc[@]}" -gt 0 || "${#a_bhout[@]}" -gt 0 || "${#a_hdirout[@]}" -gt 0 ]]; then
            a_output2+=(" - User: \"$l_user\" Home Directory: \"$l_home\"" "${a_dot_file[@]}" "${a_netrc[@]}" "${a_bhout[@]}" "${a_hdirout[@]}")
        fi
        [ "${#a_netrc_warn[@]}" -gt 0 ] && a_output3+=(" - User: \"$l_user\" Home Directory: \"$l_home\"" "${a_netrc_warn[@]}")
    done <<< "$(printf '%s\n' "${a_user_and_home[@]}")"

    if [ "${#a_output2[@]}" -le 0 ]; then
        log_pass "All user dot files are secure"
        [ "${#a_output3[@]}" -gt 0 ] && printf '%s\n' "  ** WARNING **" "${a_output3[@]}"
    else
        log_fail "Some user dot files are insecure"
        printf '%s\n' "- * Reasons for audit failure * :" "${a_output2[@]}"
        [ "${#a_output3[@]}" -gt 0 ] && printf '%s\n' "  ** WARNING **" "${a_output3[@]}"
    fi
}

main(){

  print_header "RHEL CIS Level 1 Audit Starting..."
  # 1.1.1 Check Filesystem Kernel Modules
  print_header "1.1.1 - Configure Filesystem Kernel Module"
  check_kernel_module "cramfs" "fs"
  check_kernel_module "freevxfs" "fs"
  check_kernel_module "hfs" "fs"
  check_kernel_module "hfsplus" "fs"
  check_kernel_module "jffs2" "fs"
  check_kernel_module "squashfs" "fs"
  check_kernel_module "udf" "fs"
  check_kernel_module "usb-storage" "drivers"

  # 1.1.2 Check Filesystem Partitions
  print_header "1.1.2. - Configure Filesystem Partions"
  check_mount_and_options "/tmp"
  check_mount_and_options "/dev/shm"
  check_mount_and_options "/home"
  check_mount_and_options "/var"
  check_mount_and_options "/var/tmp"
  check_mount_and_options "/var/log"
  check_mount_and_options "/var/log/audit"

  # 1.2.1.2 Package Repositories
  print_header "1.2.1.2 - Configure Package Updates"
  gpgcheck

  # 1.3 Mandatory Access Control
  print_header "1.3.1 Mandatory Access Control"
  check_libselinux_installed
  check_selinux_disabled
  check_selinuxtype
  check_selinux_mode
  check_selinux_tools_not_installed "mcstrans"
  check_selinux_tools_not_installed "setroubleshoot"


  # 1.4 Configure Bootloader
  print_header "1.4 Configure Bootloader"
  check_grub_password_set
  check_bootloader

  # 1.5 Additional Process Hardening
  print_header "1.5 Configure Additional Process Hardening"
  check_address_space_layout
  check_ptrace_scope
  check_core_dump_tracebacks
  check_core_dump_storage

  # 1.6 Check System Wide Crpto
  print_header "1.6 Configure system wide crypto policy"
  check_crypto_policy_not_legacy
  check_sshd_crypto_policy_defined
  check_sha1_not_in_crypto_policy
  check_mac_truncated_64_not_used
  check_cbc_policy

  # 1.7 Command Line Banners
  print_header "1.7 Configure Command Line Warning Banners"
  check_motd
  check_banner_for_os_info "/etc/issue"
  check_banner_for_os_info "/etc/issue.net"
  check_banner_file_permissions "/etc/motd"
  check_banner_file_permissions "/etc/issue"
  check_banner_file_permissions "/etc/issue.net"

  # 1.8 Check GNOME Display Manager
  print_header "1.8 Configure GNOME Display Manager"
  check_package_not_installed "gdm"
  check_gdm_banner
  ensure_gdm_disable_user_list_enabled
  check_gdm_screen_locks
  check_gdm_screen_locks_permission
  check_gdm_automatic_mounting
  check_gdm_automatic_mounting_permission
  confirm_gdm_autorun-never
  confirm_gdm_autorun-never_permission
  check_gdm_enable_not_true

  # 2.1 Services
  print_header "2.1 Configure Server Services"
  check_package_not_installed "autofs"
  check_package_not_installed "avahi"
  check_package_not_installed "dhcp-server"
  check_package_not_installed "bind"
  check_package_not_installed "dnsmasq"
  check_package_not_installed "samba"
  check_package_not_installed "vsftpd"
  check_package_not_installed "dovecot cyrus-imapd"
  check_package_not_installed "nfs-utils"
  check_package_not_installed "ypserv"
  check_package_not_installed "cups"
  check_package_not_installed "rpcbind"
  check_package_not_installed "rsync-daemon"
  check_package_not_installed "net-snmp"
  check_package_not_installed "telnet-server"
  check_package_not_installed "tftp-server"
  check_package_not_installed "squid"
  check_package_not_installed "http nginx"
  check_package_not_installed "xinetd"
  check_package_not_installed "xorg-x11-server-common"
  check_mta_config

  # 2.2 Client Services
  print_header "2.2 Configure Client Services"
  check_package_not_installed "ftp"
  check_package_not_installed "ypbind"
  check_package_not_installed "telnet"
  check_package_not_installed "tftp"

  # 2.3 Time Synchronization
  print_header "2.3 Configure Time Synchronization"
  check_package_installed "chrony"
  check_chrony_servers_configured
  check_chronyd_not_running_as_root

  print_header "2.4 Job Schedulers"
  check_cron_service_enabled_and_active
  check_crontab_permissions
  check_path_permissions "/etc/cron.hourly" 700
  check_path_permissions "/etc/cron.daily" 700
  check_path_permissions "/etc/cron.weekly" 700
  check_path_permissions "/etc/cron.monthly" 700
  check_path_permissions "/etc/cron.d" 700
  check_path_permissions "/etc/cron.allow" 640
  check_path_permissions "/etc/at.allow" 640

  print_header "3.1 Configure Network Devices"
  check_wireless_modules_blocked
  check_package_not_installed "bluez"

  print_header "3.3 Configure Network Kernel Parameters"
  check_kernel_parameters "3.3.1 - Ensure IP forwarding is disabled" \
    "net.ipv4.ip_forward=0" \
    "net.ipv6.conf.all.forwarding=0"

  check_kernel_parameters "3.3.2 - Ensure packet redirect sending is disabled" \
    "net.ipv4.conf.all.send_redirects=0" \
    "net.ipv4.conf.default.send_redirects=0"

  check_kernel_parameters "3.3.3 - Ensure bogus ICMP responses are ignored" \
    "net.ipv4.icmp_ignore_bogus_error_responses=1"

  check_kernel_parameters "3.3.4 - Ensure broadcast ICMP requests are ignored" \
    "net.ipv4.icmp_echo_ignore_broadcasts=1"

  check_kernel_parameters "3.3.5 - Ensure icmp redirects are not accepted" \
    "net.ipv4.conf.all.accept_redirects=0" \
    "net.ipv4.conf.default.accept_redirects=0" \
    "net.ipv6.conf.all.accept_redirects=0" \
    "net.ipv6.conf.default.accept_redirects=0"

  check_kernel_parameters "3.3.6 - Ensure secure icmp redirects are not accepted" \
    "net.ipv4.conf.all.secure_redirects=0" \
    "net.ipv4.conf.default.secure_redirects=0"

  check_kernel_parameters "3.3.7 - Ensure reverse path filtering is enabled" \
    "net.ipv4.conf.all.rp_filter=1" \
    "net.ipv4.conf.default.rp_filter=1"

  check_kernel_parameters "3.3.8 - Ensure source routed packets are not accepted" \
    "net.ipv4.conf.all.accept_source_route=0" \
    "net.ipv4.conf.default.accept_source_route=0" \
    "net.ipv6.conf.all.accept_source_route=0" \
    "net.ipv6.conf.default.accept_source_route=0"

  check_kernel_parameters "3.3.9 Ensure suspicious packets are logged" \
    "net.ipv4.conf.all.log_martians=1" \
    "net.ipv4.conf.default.log_martians=1"

  check_kernel_parameters "3.3.10 - Ensure tcp syn cookies is enabled" \
    "net.ipv4.tcp_syncookies=1"

  check_kernel_parameters "3.3.11 - Ensure ipv6 router advertisements are not accepted" \
    "net.ipv6.conf.all.accept_ra=0" \
    "net.ipv6.conf.default.accept_ra 0"

  print_header "4.1 Configure a firewall utility"
  check_package_installed "nftables"
  check_firewall_status

  print_header "4.3 Configure NFTables"
  check_nftables_base_chains
  check_nftables_default_drop_policy
  check_nftables_loopback_traffic

  print_header "5.1 Configure SSH Server"
  check_sshd_config_permissions
  check_ssh_private_key_permissions
  check_ssh_public_key_permissions
  check_sshd_ciphers_strength
  check_sshd_kexalgorithms_strength
  check_sshd_macs_strength
  check_sshd_access_controls
  check_sshd_banner_configured
  check_sshd_idle_timeout
  check_sshd_hostbased_authentication
  check_sshd_ignore_rhosts
  check_sshd_login_grace_time
  check_sshd_loglevel
  check_sshd_max_auth_tries
  check_sshd_max_startups
  check_sshd_max_sessions
  check_sshd_permit_empty_passwords
  check_sshd_permit_root_login
  check_sshd_permit_user_environment
  check_sshd_use_pam

  print_header "5.2 Configure privilege escalation"
  check_sudo_installed
  check_sudo_use_pty
  check_sudo_logfile_defined
  check_sudo_authentication_required
  check_sudo_timestamp_timeout
  check_su_restriction_via_pam_wheel

  print_header "5.3 Pluggable Authentication Modules"
  check_package_installed "pam"
  check_package_installed "authselect"
  check_package_installed "libpwquality"
  check_pam_modules_in_authselect
  check_pam_faillock_module
  check_pam_pwquality_module
  check_pam_pwhistory_module
  check_pam_unix_module
  check_faillock_deny_setting
  check_faillock_unlock_time
  check_pwquality_difok_setting
  check_pwquality_minlen_setting
  check_pwquality_maxrepeat_setting
  check_pwquality_maxsequence_setting
  check_pwquality_dictcheck_setting
  check_pwquality_enforce_for_root
  check_password_reuse_remember_setting
  check_pwhistory_enforce_for_root
  check_pwhistory_use_authtok
  check_pam_unix_nullok_disabled
  check_pam_unix_remember_not_set
  check_pam_unix_password_hashing
  check_pam_unix_use_authtok

  print_header "5.4.1 - Configure shadow password suite parameters"
  check_pass_max_days
  check_pass_warn_age
  check_encrypt_method
  check_password_inactive_setting
  check_future_password_changes

  print_header "5.4.2 Configure root and system accounts and environment"
  check_uid_0_users
  check_gid_0_users
  check_gid_0_group
  check_root_password_or_locked
  check_root_path_safety
  check_root_umask
  check_system_account_shells
  check_nonroot_shell_lock_status

  print_header "5.4.3 Configure user default environment"
  check_tmout_configuration
  check_default_user_umask

  print_header "6.1 Configure Integrity Checking"
  check_package_installed "aide"
  check_aide_scheduled
  check_aide_audit_tool_integrity

  print_header "6.2 System Logging"
  check_systemd_journald_status
  check_single_logging_system
  audit_systemd_journal_upload
  audit_systemd_journal_remote_disabled
  audit_journald_forward_to_syslog
  audit_journald_compress_yes
  audit_journald_storage_persistent
  audit_rsyslog_service_status
  audit_journald_forward_to_rsyslog
  audit_rsyslog_file_create_mode
  audit_rsyslog_no_remote_logs
  audit_var_log_permissions

  print_header "7.1 System File Permissions"
  audit_file_perms_ownership "/etc/passwd" "644" "root" "root"
  audit_file_perms_ownership "/etc/passwd-" "644" "root" "root"
  audit_file_perms_ownership "/etc/group" "644" "root" "root"
  audit_file_perms_ownership "/etc/group-" "644" "root" "root"
  audit_file_perms_ownership "/etc/shadow" "000" "root" "root"
  audit_file_perms_ownership "/etc/shadow-" "000" "root" "root"
  audit_file_perms_ownership "/etc/gshadow" "000" "root" "root"
  audit_file_perms_ownership "/etc/gshadow-" "000" "root" "root"
  audit_file_perms_ownership "/etc/shells" "644" "root" "root"
  audit_file_perms_ownership "/etc/security/opasswd.old" "600" "root" "root"
  check_world_writable_files_and_dirs
  check_nouser_nogroup_files

  print_header "7.2 Local User and Group Settings"
  check_shadowed_passwords
  check_users_have_passwords
  check_gids_exist_in_group
  check_duplicate_uids
  check_duplicate_gids
  check_duplicate_usernames
  check_duplicate_groupnames
  check_local_user_home_dirs
  check_user_dot_files

  summary
}


