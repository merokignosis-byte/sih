#!/bin/bash
# Access Control Hardening Script
# Covers: SSH Server, Privilege Escalation, PAM

MODE="${1:-scan}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="$SCRIPT_DIR/../hardening.db"
BACKUP_DIR="$SCRIPT_DIR/../backups/access_control"
TOPIC="Access Control"

mkdir -p "$BACKUP_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
FIXED_CHECKS=0

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[FAIL]${NC} $1"; }
log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; }

save_config() {
    python3 -c "
import sqlite3
conn = sqlite3.connect('$DB_PATH')
cursor = conn.cursor()
cursor.execute('''
    INSERT OR REPLACE INTO configurations 
    (topic, rule_id, rule_name, original_value, current_value, status)
    VALUES (?, ?, ?, ?, ?, 'stored')
''', ('$TOPIC', '$1', '''$2''', '''$3''', '''${4:-$3}'''))
conn.commit()
conn.close()
"
}

get_original_config() {
    python3 -c "
import sqlite3
conn = sqlite3.connect('$DB_PATH')
cursor = conn.cursor()
cursor.execute('SELECT original_value FROM configurations WHERE topic=? AND rule_id=?', ('$TOPIC', '$1'))
result = cursor.fetchone()
conn.close()
print(result[0] if result else '')
"
}

# ============================================================================
# 6.1 SSH Server Configuration
# ============================================================================

check_ssh_config() {
    local rule_id="SSH-CONFIG-PERMS"
    local rule_name="Ensure permissions on /etc/ssh/sshd_config are configured"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if [ -f /etc/ssh/sshd_config ]; then
            local perms=$(stat -c %a /etc/ssh/sshd_config)
            local owner=$(stat -c %U /etc/ssh/sshd_config)
            local group=$(stat -c %G /etc/ssh/sshd_config)
            
            if [ "$perms" = "600" ] && [ "$owner" = "root" ] && [ "$group" = "root" ]; then
                log_pass "SSH config permissions correct: 600 root:root"
                ((PASSED_CHECKS++))
                return 0
            else
                log_error "SSH config permissions incorrect: $perms $owner:$group"
                ((FAILED_CHECKS++))
                return 1
            fi
        fi
        
    elif [ "$MODE" = "fix" ]; then
        if [ -f /etc/ssh/sshd_config ]; then
            local current=$(stat -c "%a %U:%G" /etc/ssh/sshd_config)
            save_config "$rule_id" "$rule_name" "$current"
            
            chown root:root /etc/ssh/sshd_config
            chmod 600 /etc/ssh/sshd_config
            log_info "Set SSH config permissions to 600 root:root"
            ((FIXED_CHECKS++))
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        local original=$(get_original_config "$rule_id")
        if [ -n "$original" ] && [ -f /etc/ssh/sshd_config ]; then
            local orig_perms=$(echo "$original" | awk '{print $1}')
            chmod "$orig_perms" /etc/ssh/sshd_config 2>/dev/null
            log_info "Restored SSH config permissions"
        fi
    fi
}

check_sshd_parameter() {
    local param="$1"
    local expected_value="$2"
    local rule_id="SSH-PARAM-$(echo $param | tr '[:lower:]' '[:upper:]')"
    local rule_name="Ensure sshd $param is $expected_value"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        local current=$(sshd -T 2>/dev/null | grep "^$param " | awk '{print $2}')
        
        if [ "$current" = "$expected_value" ]; then
            log_pass "SSH $param = $expected_value"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "SSH $param = $current (expected: $expected_value)"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        local current=$(sshd -T 2>/dev/null | grep "^$param " | awk '{print $2}')
        
        if [ -z "$current" ]; then
            current="not_set"
        fi
        
        save_config "$rule_id" "$rule_name" "$current"
        
        # Backup sshd_config
        cp /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.$(date +%Y%m%d_%H%M%S)"
        
        # Update or add parameter
        if grep -q "^$param " /etc/ssh/sshd_config; then
            sed -i "s/^$param .*/$param $expected_value/" /etc/ssh/sshd_config
        elif grep -q "^#$param " /etc/ssh/sshd_config; then
            sed -i "s/^#$param .*/$param $expected_value/" /etc/ssh/sshd_config
        else
            echo "$param $expected_value" >> /etc/ssh/sshd_config
        fi
        
        log_info "Set SSH $param = $expected_value"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        local backup=$(ls -t "$BACKUP_DIR"/sshd_config.* 2>/dev/null | head -1)
        if [ -n "$backup" ]; then
            cp "$backup" /etc/ssh/sshd_config
            systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null
            log_info "Restored SSH configuration"
        fi
    fi
}

check_all_ssh_parameters() {
    log_info "=== SSH Server Configuration ==="
    
    check_ssh_config
    check_sshd_parameter "PermitRootLogin" "no"
    check_sshd_parameter "PermitEmptyPasswords" "no"
    check_sshd_parameter "PermitUserEnvironment" "no"
    check_sshd_parameter "HostbasedAuthentication" "no"
    check_sshd_parameter "IgnoreRhosts" "yes"
    check_sshd_parameter "X11Forwarding" "no"
    check_sshd_parameter "MaxAuthTries" "4"
    check_sshd_parameter "MaxSessions" "10"
    check_sshd_parameter "LoginGraceTime" "60"
    check_sshd_parameter "ClientAliveInterval" "300"
    check_sshd_parameter "ClientAliveCountMax" "3"
    check_sshd_parameter "LogLevel" "INFO"
    check_sshd_parameter "UsePAM" "yes"
    check_sshd_parameter "GSSAPIAuthentication" "no"
}

# ============================================================================
# 6.2 Privilege Escalation - Sudo
# ============================================================================

check_sudo_installed() {
    local rule_id="SUDO-INSTALLED"
    local rule_name="Ensure sudo is installed"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if command -v sudo >/dev/null 2>&1; then
            log_pass "sudo is installed"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "sudo is not installed"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        if ! command -v sudo >/dev/null 2>&1; then
            save_config "$rule_id" "$rule_name" "not_installed"
            apt-get install -y sudo
            log_info "Installed sudo"
            ((FIXED_CHECKS++))
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        local original=$(get_original_config "$rule_id")
        if [ "$original" = "not_installed" ]; then
            apt-get remove -y sudo
            log_info "Removed sudo"
        fi
    fi
}

check_sudo_pty() {
    local rule_id="SUDO-USE-PTY"
    local rule_name="Ensure sudo commands use pty"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if grep -rq "^Defaults.*use_pty" /etc/sudoers /etc/sudoers.d/; then
            log_pass "sudo use_pty is configured"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "sudo use_pty is not configured"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        save_config "$rule_id" "$rule_name" "not_configured"
        
        cp /etc/sudoers "$BACKUP_DIR/sudoers.$(date +%Y%m%d_%H%M%S)"
        
        if ! grep -q "^Defaults.*use_pty" /etc/sudoers; then
            echo "Defaults use_pty" >> /etc/sudoers.d/hardening
        fi
        
        log_info "Configured sudo use_pty"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        rm -f /etc/sudoers.d/hardening
        log_info "Removed sudo hardening configuration"
    fi
}

check_sudo_logfile() {
    local rule_id="SUDO-LOGFILE"
    local rule_name="Ensure sudo log file exists"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if grep -rq "^Defaults.*logfile=" /etc/sudoers /etc/sudoers.d/; then
            log_pass "sudo logfile is configured"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "sudo logfile is not configured"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        save_config "$rule_id" "$rule_name" "not_configured"
        
        if ! grep -q "^Defaults.*logfile=" /etc/sudoers /etc/sudoers.d/* 2>/dev/null; then
            echo 'Defaults logfile="/var/log/sudo.log"' >> /etc/sudoers.d/hardening
        fi
        
        log_info "Configured sudo logfile"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        sed -i '/logfile=/d' /etc/sudoers.d/hardening 2>/dev/null
        log_info "Removed sudo logfile configuration"
    fi
}

check_su_restricted() {
    local rule_id="SU-RESTRICTED"
    local rule_name="Ensure access to the su command is restricted"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if grep -q "^auth.*required.*pam_wheel.so" /etc/pam.d/su; then
            log_pass "su command is restricted"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "su command is not restricted"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        cp /etc/pam.d/su "$BACKUP_DIR/su.$(date +%Y%m%d_%H%M%S)"
        save_config "$rule_id" "$rule_name" "not_restricted"
        
        if ! grep -q "^auth.*required.*pam_wheel.so" /etc/pam.d/su; then
            echo "auth required pam_wheel.so use_uid" >> /etc/pam.d/su
        fi
        
        # Create wheel group if it doesn't exist
        if ! getent group wheel >/dev/null; then
            groupadd wheel
        fi
        
        log_info "Restricted su command to wheel group"
        log_warn "Add authorized users to wheel group: usermod -aG wheel <username>"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        local backup=$(ls -t "$BACKUP_DIR"/su.* 2>/dev/null | head -1)
        if [ -n "$backup" ]; then
            cp "$backup" /etc/pam.d/su
            log_info "Restored su configuration"
        fi
    fi
}

# ============================================================================
# 6.3 PAM Configuration
# ============================================================================

check_pam_package() {
    local package="$1"
    local rule_id="PAM-PKG-$(echo $package | tr '-' '_' | tr '[:lower:]' '[:upper:]')"
    local rule_name="Ensure $package is installed"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if dpkg -l | grep -q "^ii.*$package"; then
            log_pass "$package is installed"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "$package is not installed"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        if ! dpkg -l | grep -q "^ii.*$package"; then
            save_config "$rule_id" "$rule_name" "not_installed"
            apt-get install -y "$package"
            log_info "Installed $package"
            ((FIXED_CHECKS++))
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        local original=$(get_original_config "$rule_id")
        if [ "$original" = "not_installed" ]; then
            apt-get remove -y "$package"
            log_info "Removed $package"
        fi
    fi
}

check_pam_pwquality() {
    local rule_id="PAM-PWQUALITY"
    local rule_name="Ensure password quality requirements are configured"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if [ -f /etc/security/pwquality.conf ]; then
            local minlen=$(grep "^minlen" /etc/security/pwquality.conf | awk -F= '{print $2}' | tr -d ' ')
            local minclass=$(grep "^minclass" /etc/security/pwquality.conf | awk -F= '{print $2}' | tr -d ' ')
            
            if [ "${minlen:-0}" -ge 14 ]; then
                log_pass "Password quality is configured (minlen >= 14)"
                ((PASSED_CHECKS++))
                return 0
            else
                log_error "Password quality not properly configured"
                ((FAILED_CHECKS++))
                return 1
            fi
        else
            log_error "pwquality.conf not found"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        if [ -f /etc/security/pwquality.conf ]; then
            cp /etc/security/pwquality.conf "$BACKUP_DIR/pwquality.conf.$(date +%Y%m%d_%H%M%S)"
            save_config "$rule_id" "$rule_name" "not_configured"
            
            # Configure password quality
            sed -i 's/^# minlen.*/minlen = 14/' /etc/security/pwquality.conf
            sed -i 's/^# minclass.*/minclass = 4/' /etc/security/pwquality.conf
            sed -i 's/^# dcredit.*/dcredit = -1/' /etc/security/pwquality.conf
            sed -i 's/^# ucredit.*/ucredit = -1/' /etc/security/pwquality.conf
            sed -i 's/^# lcredit.*/lcredit = -1/' /etc/security/pwquality.conf
            sed -i 's/^# ocredit.*/ocredit = -1/' /etc/security/pwquality.conf
            
            log_info "Configured password quality requirements"
            ((FIXED_CHECKS++))
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        local backup=$(ls -t "$BACKUP_DIR"/pwquality.conf.* 2>/dev/null | head -1)
        if [ -n "$backup" ]; then
            cp "$backup" /etc/security/pwquality.conf
            log_info "Restored pwquality configuration"
        fi
    fi
}

check_pam_faillock() {
    local rule_id="PAM-FAILLOCK"
    local rule_name="Ensure password failed attempts lockout is configured"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if grep -q "pam_faillock" /etc/pam.d/common-auth 2>/dev/null; then
            log_pass "Account lockout is configured"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "Account lockout is not configured"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        cp /etc/pam.d/common-auth "$BACKUP_DIR/common-auth.$(date +%Y%m%d_%H%M%S)" 2>/dev/null
        save_config "$rule_id" "$rule_name" "not_configured"
        
        log_warn "Manual configuration required for pam_faillock"
        log_info "Add to /etc/pam.d/common-auth:"
        log_info "auth required pam_faillock.so preauth silent audit deny=5 unlock_time=900"
        log_info "auth required pam_faillock.so authfail audit deny=5 unlock_time=900"
        
    elif [ "$MODE" = "rollback" ]; then
        local backup=$(ls -t "$BACKUP_DIR"/common-auth.* 2>/dev/null | head -1)
        if [ -n "$backup" ]; then
            cp "$backup" /etc/pam.d/common-auth
            log_info "Restored PAM auth configuration"
        fi
    fi
}

# ============================================================================
# Main Execution
# ============================================================================

main() {
    echo "========================================================================"
    echo "Access Control Hardening Script"
    echo "Mode: $MODE"
    echo "========================================================================"
    
    if [ "$MODE" = "scan" ] || [ "$MODE" = "fix" ]; then
        check_all_ssh_parameters
        
        log_info ""
        log_info "=== Privilege Escalation ==="
        check_sudo_installed
        check_sudo_pty
        check_sudo_logfile
        check_su_restricted
        
        log_info ""
        log_info "=== PAM Configuration ==="
        check_pam_package "libpam-pwquality"
        check_pam_pwquality
        check_pam_faillock
        
        echo ""
        echo "========================================================================"
        echo "Summary"
        echo "========================================================================"
        echo "Total Checks: $TOTAL_CHECKS"
        
        if [ "$MODE" = "scan" ]; then
            echo "Passed: $PASSED_CHECKS"
            echo "Failed: $FAILED_CHECKS"
            
            if [ $FAILED_CHECKS -eq 0 ]; then
                log_pass "All access control checks passed!"
            else
                log_warn "$FAILED_CHECKS checks failed. Run with 'fix' mode to remediate."
            fi
        else
            echo "Fixed: $FIXED_CHECKS"
            log_info "Fixes applied. Run 'scan' mode to verify."
            log_warn "SSH configuration changes require: systemctl restart sshd"
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        log_info "Rolling back access control configurations..."
        check_all_ssh_parameters
        check_sudo_pty
        check_sudo_logfile
        check_su_restricted
        check_pam_pwquality
        log_info "Rollback completed"
    else
        echo "Usage: $0 {scan|fix|rollback}"
        exit 1
    fi
}

main
