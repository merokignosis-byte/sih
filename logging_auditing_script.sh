#!/bin/bash
# Logging and Auditing Hardening Script
# Covers: System Logging (journald, rsyslog), Auditd, AIDE

MODE="${1:-scan}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="$SCRIPT_DIR/../hardening.db"
BACKUP_DIR="$SCRIPT_DIR/../backups/logging_auditing"
TOPIC="Logging and Auditing"

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
# 8.1 System Logging - journald
# ============================================================================

check_journald_enabled() {
    local rule_id="LOG-JOURNALD-ENABLED"
    local rule_name="Ensure journald service is enabled and active"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if systemctl is-active systemd-journald 2>/dev/null | grep -q "active"; then
            log_pass "journald is active"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "journald is not active"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        save_config "$rule_id" "$rule_name" "inactive"
        systemctl enable systemd-journald
        systemctl start systemd-journald
        log_info "Enabled and started journald"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        log_info "journald is a core system service - no rollback"
    fi
}

check_journald_compression() {
    local rule_id="LOG-JOURNALD-COMPRESS"
    local rule_name="Ensure journald log file rotation is configured"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if [ -f /etc/systemd/journald.conf ]; then
            local compress=$(grep "^Compress=" /etc/systemd/journald.conf | cut -d= -f2)
            local max_file_sec=$(grep "^MaxFileSec=" /etc/systemd/journald.conf | cut -d= -f2)
            
            if [ "$compress" = "yes" ] || [ -n "$max_file_sec" ]; then
                log_pass "journald rotation is configured"
                ((PASSED_CHECKS++))
                return 0
            else
                log_error "journald rotation not configured"
                ((FAILED_CHECKS++))
                return 1
            fi
        fi
        
    elif [ "$MODE" = "fix" ]; then
        if [ -f /etc/systemd/journald.conf ]; then
            cp /etc/systemd/journald.conf "$BACKUP_DIR/journald.conf.$(date +%Y%m%d_%H%M%S)"
            save_config "$rule_id" "$rule_name" "not_configured"
            
            sed -i 's/^#Compress=.*/Compress=yes/' /etc/systemd/journald.conf
            sed -i 's/^#SystemMaxUse=.*/SystemMaxUse=1G/' /etc/systemd/journald.conf
            sed -i 's/^#MaxFileSec=.*/MaxFileSec=1month/' /etc/systemd/journald.conf
            
            systemctl restart systemd-journald
            log_info "Configured journald rotation"
            ((FIXED_CHECKS++))
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        local backup=$(ls -t "$BACKUP_DIR"/journald.conf.* 2>/dev/null | head -1)
        if [ -n "$backup" ]; then
            cp "$backup" /etc/systemd/journald.conf
            systemctl restart systemd-journald
            log_info "Restored journald configuration"
        fi
    fi
}

# ============================================================================
# 8.2 System Logging - rsyslog
# ============================================================================

check_rsyslog_installed() {
    local rule_id="LOG-RSYSLOG-INSTALLED"
    local rule_name="Ensure rsyslog is installed"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if dpkg -l | grep -q "^ii.*rsyslog"; then
            log_pass "rsyslog is installed"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "rsyslog is not installed"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        if ! dpkg -l | grep -q "^ii.*rsyslog"; then
            save_config "$rule_id" "$rule_name" "not_installed"
            apt-get install -y rsyslog
            log_info "Installed rsyslog"
            ((FIXED_CHECKS++))
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        local original=$(get_original_config "$rule_id")
        if [ "$original" = "not_installed" ]; then
            apt-get remove -y rsyslog
            log_info "Removed rsyslog"
        fi
    fi
}

check_rsyslog_enabled() {
    local rule_id="LOG-RSYSLOG-ENABLED"
    local rule_name="Ensure rsyslog service is enabled and active"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if systemctl is-enabled rsyslog 2>/dev/null | grep -q "enabled" && \
           systemctl is-active rsyslog 2>/dev/null | grep -q "active"; then
            log_pass "rsyslog is enabled and active"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "rsyslog is not properly configured"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        save_config "$rule_id" "$rule_name" "not_enabled"
        systemctl enable rsyslog
        systemctl start rsyslog
        log_info "Enabled and started rsyslog"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        systemctl disable rsyslog 2>/dev/null
        systemctl stop rsyslog 2>/dev/null
        log_info "Disabled rsyslog"
    fi
}

check_rsyslog_file_permissions() {
    local rule_id="LOG-RSYSLOG-PERMS"
    local rule_name="Ensure rsyslog log file creation mode is configured"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if grep -q '^\$FileCreateMode 0640' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null; then
            log_pass "rsyslog file permissions configured"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "rsyslog file permissions not configured"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        cp /etc/rsyslog.conf "$BACKUP_DIR/rsyslog.conf.$(date +%Y%m%d_%H%M%S)"
        save_config "$rule_id" "$rule_name" "not_configured"
        
        if ! grep -q '^\$FileCreateMode' /etc/rsyslog.conf; then
            echo '$FileCreateMode 0640' >> /etc/rsyslog.conf
        else
            sed -i 's/^\$FileCreateMode.*/$FileCreateMode 0640/' /etc/rsyslog.conf
        fi
        
        systemctl restart rsyslog
        log_info "Configured rsyslog file permissions"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        local backup=$(ls -t "$BACKUP_DIR"/rsyslog.conf.* 2>/dev/null | head -1)
        if [ -n "$backup" ]; then
            cp "$backup" /etc/rsyslog.conf
            systemctl restart rsyslog
            log_info "Restored rsyslog configuration"
        fi
    fi
}

check_logrotate() {
    local rule_id="LOG-LOGROTATE"
    local rule_name="Ensure logrotate is configured"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if [ -f /etc/logrotate.conf ] && [ -d /etc/logrotate.d ]; then
            log_pass "logrotate is configured"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "logrotate is not properly configured"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        if ! command -v logrotate >/dev/null; then
            apt-get install -y logrotate
            log_info "Installed logrotate"
            ((FIXED_CHECKS++))
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        log_info "logrotate configuration maintained"
    fi
}

check_logfile_permissions() {
    local rule_id="LOG-FILE-PERMS"
    local rule_name="Ensure access to all logfiles has been configured"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        local bad_perms=$(find /var/log -type f -perm /027 2>/dev/null | wc -l)
        
        if [ "$bad_perms" -eq 0 ]; then
            log_pass "Log file permissions are correct"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "Found $bad_perms log files with incorrect permissions"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        save_config "$rule_id" "$rule_name" "permissions_mixed"
        
        find /var/log -type f -exec chmod g-wx,o-rwx {} \;
        log_info "Fixed log file permissions"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        log_warn "Log file permission rollback not recommended"
    fi
}

# ============================================================================
# 8.3 System Auditing - auditd
# ============================================================================

check_auditd_installed() {
    local rule_id="AUD-AUDITD-INSTALLED"
    local rule_name="Ensure auditd packages are installed"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if dpkg -l | grep -q "^ii.*auditd"; then
            log_pass "auditd is installed"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "auditd is not installed"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        if ! dpkg -l | grep -q "^ii.*auditd"; then
            save_config "$rule_id" "$rule_name" "not_installed"
            apt-get install -y auditd audispd-plugins
            log_info "Installed auditd"
            ((FIXED_CHECKS++))
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        local original=$(get_original_config "$rule_id")
        if [ "$original" = "not_installed" ]; then
            apt-get remove -y auditd audispd-plugins
            log_info "Removed auditd"
        fi
    fi
}

check_auditd_enabled() {
    local rule_id="AUD-AUDITD-ENABLED"
    local rule_name="Ensure auditd service is enabled and active"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if systemctl is-enabled auditd 2>/dev/null | grep -q "enabled" && \
           systemctl is-active auditd 2>/dev/null | grep -q "active"; then
            log_pass "auditd is enabled and active"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "auditd is not properly configured"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        save_config "$rule_id" "$rule_name" "not_enabled"
        systemctl enable auditd
        systemctl start auditd
        log_info "Enabled and started auditd"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        systemctl disable auditd 2>/dev/null
        systemctl stop auditd 2>/dev/null
        log_info "Disabled auditd"
    fi
}

check_audit_log_storage() {
    local rule_id="AUD-LOG-STORAGE"
    local rule_name="Ensure audit log storage size is configured"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if [ -f /etc/audit/auditd.conf ]; then
            local max_log_file=$(grep "^max_log_file " /etc/audit/auditd.conf | awk '{print $3}')
            
            if [ -n "$max_log_file" ] && [ "$max_log_file" -ge 8 ]; then
                log_pass "Audit log storage configured: ${max_log_file}MB"
                ((PASSED_CHECKS++))
                return 0
            else
                log_error "Audit log storage not properly configured"
                ((FAILED_CHECKS++))
                return 1
            fi
        fi
        
    elif [ "$MODE" = "fix" ]; then
        if [ -f /etc/audit/auditd.conf ]; then
            cp /etc/audit/auditd.conf "$BACKUP_DIR/auditd.conf.$(date +%Y%m%d_%H%M%S)"
            save_config "$rule_id" "$rule_name" "not_configured"
            
            sed -i 's/^max_log_file .*/max_log_file = 10/' /etc/audit/auditd.conf
            sed -i 's/^max_log_file_action .*/max_log_file_action = keep_logs/' /etc/audit/auditd.conf
            
            service auditd restart
            log_info "Configured audit log storage"
            ((FIXED_CHECKS++))
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        local backup=$(ls -t "$BACKUP_DIR"/auditd.conf.* 2>/dev/null | head -1)
        if [ -n "$backup" ]; then
            cp "$backup" /etc/audit/auditd.conf
            service auditd restart
            log_info "Restored auditd configuration"
        fi
    fi
}

add_audit_rule() {
    local rule="$1"
    local description="$2"
    local rule_id="$3"
    
    if ! grep -q "$rule" /etc/audit/rules.d/hardening.rules 2>/dev/null; then
        echo "# $description" >> /etc/audit/rules.d/hardening.rules
        echo "$rule" >> /etc/audit/rules.d/hardening.rules
        echo "" >> /etc/audit/rules.d/hardening.rules
    fi
}

check_audit_rules() {
    local rule_id="AUD-RULES"
    local rule_name="Ensure audit rules are configured"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if [ -f /etc/audit/rules.d/hardening.rules ]; then
            log_pass "Custom audit rules are configured"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "Custom audit rules not configured"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        save_config "$rule_id" "$rule_name" "not_configured"
        
        # Create hardening rules file
        cat > /etc/audit/rules.d/hardening.rules << 'EOF'
# Audit Rules for System Hardening

# Time changes
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# User/Group changes
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Network changes
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/network -p wa -k system-locale

# Login/Logout events
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins

# Session initiation
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins

# Sudoers changes
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope

# Kernel module changes
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

EOF
        
        # Load rules
        augenrules --load
        log_info "Configured audit rules"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        rm -f /etc/audit/rules.d/hardening.rules
        augenrules --load
        log_info "Removed custom audit rules"
    fi
}

# ============================================================================
# 8.4 Integrity Checking - AIDE
# ============================================================================

check_aide_installed() {
    local rule_id="AUD-AIDE-INSTALLED"
    local rule_name="Ensure AIDE is installed"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if command -v aide >/dev/null 2>&1; then
            log_pass "AIDE is installed"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "AIDE is not installed"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        if ! command -v aide >/dev/null 2>&1; then
            save_config "$rule_id" "$rule_name" "not_installed"
            apt-get install -y aide aide-common
            
            log_info "Installing AIDE... initializing database"
            aideinit
            log_info "AIDE installed and initialized"
            ((FIXED_CHECKS++))
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        local original=$(get_original_config "$rule_id")
        if [ "$original" = "not_installed" ]; then
            apt-get remove -y aide aide-common
            log_info "Removed AIDE"
        fi
    fi
}

check_aide_cron() {
    local rule_id="AUD-AIDE-CRON"
    local rule_name="Ensure filesystem integrity is regularly checked"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if crontab -l 2>/dev/null | grep -q aide || \
           grep -rq aide /etc/cron.* /etc/crontab 2>/dev/null; then
            log_pass "AIDE cron job is configured"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "AIDE cron job not configured"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        save_config "$rule_id" "$rule_name" "not_configured"
        
        echo "0 5 * * * /usr/bin/aide.wrapper --config /etc/aide/aide.conf --check" > /etc/cron.d/aide
        
        log_info "Configured AIDE cron job (daily at 5 AM)"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        rm -f /etc/cron.d/aide
        log_info "Removed AIDE cron job"
    fi
}

# ============================================================================
# Main Execution
# ============================================================================

main() {
    echo "========================================================================"
    echo "Logging and Auditing Hardening Script"
    echo "Mode: $MODE"
    echo "========================================================================"
    
    if [ "$MODE" = "scan" ] || [ "$MODE" = "fix" ]; then
        log_info "=== System Logging - journald ==="
        check_journald_enabled
        check_journald_compression
        
        log_info ""
        log_info "=== System Logging - rsyslog ==="
        check_rsyslog_installed
        check_rsyslog_enabled
        check_rsyslog_file_permissions
        check_logrotate
        check_logfile_permissions
        
        log_info ""
        log_info "=== System Auditing - auditd ==="
        check_auditd_installed
        check_auditd_enabled
        check_audit_log_storage
        check_audit_rules
        
        log_info ""
        log_info "=== Integrity Checking - AIDE ==="
        check_aide_installed
        check_aide_cron
        
        echo ""
        echo "========================================================================"
        echo "Summary"
        echo "========================================================================"
        echo "Total Checks: $TOTAL_CHECKS"
        
        if [ "$MODE" = "scan" ]; then
            echo "Passed: $PASSED_CHECKS"
            echo "Failed: $FAILED_CHECKS"
            
            if [ $FAILED_CHECKS -eq 0 ]; then
                log_pass "All logging and auditing checks passed!"
            else
                log_warn "$FAILED_CHECKS checks failed. Run with 'fix' mode to remediate."
            fi
        else
            echo "Fixed: $FIXED_CHECKS"
            log_info "Fixes applied. Run 'scan' mode to verify."
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        log_info "Rolling back logging and auditing configurations..."
        check_journald_compression
        check_rsyslog_installed
        check_rsyslog_file_permissions
        check_auditd_installed
        check_audit_log_storage
        check_audit_rules
        check_aide_installed
        check_aide_cron
        log_info "Rollback completed"
    else
        echo "Usage: $0 {scan|fix|rollback}"
        exit 1
    fi
}

main
