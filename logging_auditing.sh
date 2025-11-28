#!/bin/bash
# Logging and Auditing Hardening Script - Enhanced Version
# Covers: System Logging (journald, rsyslog), Auditd, AIDE
# CIS Benchmark Compliant with Manual Intervention Support

MODE="${1:-scan}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="$SCRIPT_DIR/../hardening.db"
BACKUP_DIR="$SCRIPT_DIR/../backups/logging_auditing"
TOPIC="Logging and Auditing"

mkdir -p "$BACKUP_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
FIXED_CHECKS=0
MANUAL_CHECKS=0

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[FAIL]${NC} $1"; }
log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
log_manual() { echo -e "${BLUE}[MANUAL]${NC} $1"; }

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

check_journald_persistent() {
    local rule_id="LOG-JOURNALD-PERSIST"
    local rule_name="Ensure journald is configured to persist logs to disk"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if [ -f /etc/systemd/journald.conf ]; then
            local storage=$(grep "^Storage=" /etc/systemd/journald.conf | cut -d= -f2)
            
            if [ "$storage" = "persistent" ] || [ -d /var/log/journal ]; then
                log_pass "journald persistent storage is configured"
                ((PASSED_CHECKS++))
                return 0
            else
                log_error "journald persistent storage not configured"
                ((FAILED_CHECKS++))
                return 1
            fi
        fi
        
    elif [ "$MODE" = "fix" ]; then
        if [ -f /etc/systemd/journald.conf ]; then
            cp /etc/systemd/journald.conf "$BACKUP_DIR/journald.conf.persist.$(date +%Y%m%d_%H%M%S)"
            save_config "$rule_id" "$rule_name" "not_persistent"
            
            sed -i 's/^#Storage=.*/Storage=persistent/' /etc/systemd/journald.conf
            
            # Create journal directory if it doesn't exist
            mkdir -p /var/log/journal
            systemd-tmpfiles --create --prefix /var/log/journal
            
            systemctl restart systemd-journald
            log_info "Configured journald persistent storage"
            ((FIXED_CHECKS++))
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        local backup=$(ls -t "$BACKUP_DIR"/journald.conf.persist.* 2>/dev/null | head -1)
        if [ -n "$backup" ]; then
            cp "$backup" /etc/systemd/journald.conf
            systemctl restart systemd-journald
            log_info "Restored journald persistence configuration"
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
            log_warn "rsyslog is not installed (journald may be sufficient)"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        if ! dpkg -l | grep -q "^ii.*rsyslog"; then
            log_manual "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            log_manual "MANUAL DECISION REQUIRED: rsyslog Installation"
            log_manual "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            log_manual "rsyslog is not installed. Modern systems use systemd-journald."
            log_manual ""
            log_manual "OPTIONS:"
            log_manual "1. Keep systemd-journald only (RECOMMENDED)"
            log_manual "   - No action needed"
            log_manual "   - Sufficient for most use cases"
            log_manual ""
            log_manual "2. Install rsyslog (if required by policy)"
            log_manual "   sudo apt-get install -y rsyslog"
            log_manual "   sudo systemctl enable rsyslog"
            log_manual "   sudo systemctl start rsyslog"
            log_manual "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            ((MANUAL_CHECKS++))
            save_config "$rule_id" "$rule_name" "not_installed"
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        log_info "No rollback needed for rsyslog installation check"
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
        # Check if rsyslog is installed first
        if ! dpkg -l | grep -q "^ii.*rsyslog"; then
            log_warn "rsyslog not installed - skipping service check"
            ((PASSED_CHECKS++))
            return 0
        fi
        
        # Check if service is masked first
        if systemctl is-enabled rsyslog 2>&1 | grep -q "masked"; then
            log_warn "rsyslog service is masked (systemd-journald is being used)"
            ((FAILED_CHECKS++))
            return 1
        fi
        
        if systemctl is-enabled rsyslog 2>/dev/null | grep -q "enabled" && \
           systemctl is-active rsyslog 2>/dev/null | grep -q "active"; then
            log_pass "rsyslog is enabled and active"
            ((PASSED_CHECKS++))
            return 0
        else
            local enabled_status=$(systemctl is-enabled rsyslog 2>&1)
            local active_status=$(systemctl is-active rsyslog 2>&1)
            log_error "rsyslog service not properly configured (enabled: $enabled_status, active: $active_status)"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        # Check if rsyslog is installed
        if ! dpkg -l | grep -q "^ii.*rsyslog"; then
            log_warn "rsyslog not installed - cannot enable service"
            return 0
        fi
        
        local service_status=$(systemctl is-enabled rsyslog 2>&1)
        
        # Check if service is masked
        if echo "$service_status" | grep -q "masked"; then
            log_manual "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            log_manual "CONFLICT DETECTED: rsyslog is masked by systemd"
            log_manual "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            log_manual "Your system is using systemd-journald for logging."
            log_manual "Both rsyslog and systemd-journald provide logging services."
            log_manual ""
            log_manual "WHY IS THIS MASKED?"
            log_manual "- systemd masked rsyslog to prevent conflicts"
            log_manual "- Only ONE logging daemon should run at a time"
            log_manual "- Modern systems prefer systemd-journald"
            log_manual ""
            log_manual "OPTIONS:"
            log_manual "1. Keep systemd-journald (RECOMMENDED for modern systems)"
            log_manual "   - No action needed"
            log_manual "   - Complies with audit requirements via journald"
            log_manual ""
            log_manual "2. Switch to rsyslog (if specifically required)"
            log_manual "   Run these commands manually:"
            log_manual "   sudo systemctl unmask rsyslog"
            log_manual "   sudo systemctl enable rsyslog"
            log_manual "   sudo systemctl start rsyslog"
            log_manual ""
            log_manual "3. Use both (dual logging - uses more disk space)"
            log_manual "   sudo systemctl unmask rsyslog"
            log_manual "   sudo systemctl enable rsyslog"
            log_manual "   sudo systemctl start rsyslog"
            log_manual "   Configure journald to forward to rsyslog:"
            log_manual "   echo 'ForwardToSyslog=yes' >> /etc/systemd/journald.conf"
            log_manual "   sudo systemctl restart systemd-journald"
            log_manual "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            ((MANUAL_CHECKS++))
            save_config "$rule_id" "$rule_name" "masked"
            return 2
        fi
        
        # Service is not masked - safe to enable
        save_config "$rule_id" "$rule_name" "$service_status"
        
        # Check if already enabled and active
        if systemctl is-enabled rsyslog 2>/dev/null | grep -q "enabled" && \
           systemctl is-active rsyslog 2>/dev/null | grep -q "active"; then
            log_info "rsyslog is already enabled and active"
            return 0
        fi
        
        # Enable the service
        if ! systemctl is-enabled rsyslog 2>/dev/null | grep -q "enabled"; then
            log_info "Enabling rsyslog service..."
            if systemctl enable rsyslog 2>&1 | tee /tmp/rsyslog_enable.log; then
                log_pass "rsyslog service enabled"
            else
                log_error "Failed to enable rsyslog - check /tmp/rsyslog_enable.log"
                return 1
            fi
        fi
        
        # Start the service
        if ! systemctl is-active rsyslog 2>/dev/null | grep -q "active"; then
            log_info "Starting rsyslog service..."
            if systemctl start rsyslog 2>&1 | tee /tmp/rsyslog_start.log; then
                log_pass "rsyslog service started"
                ((FIXED_CHECKS++))
            else
                log_error "Failed to start rsyslog - check /tmp/rsyslog_start.log"
                log_error "Check status with: systemctl status rsyslog"
                return 1
            fi
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        local original=$(get_original_config "$rule_id")
        
        if [ "$original" = "masked" ]; then
            log_info "Service was originally masked - not rolling back"
            return 0
        fi
        
        log_info "Disabling rsyslog service..."
        systemctl disable rsyslog 2>/dev/null
        systemctl stop rsyslog 2>/dev/null
        log_info "Disabled and stopped rsyslog"
    fi
}

check_rsyslog_default_perms() {
    local rule_id="LOG-RSYSLOG-DEFPERMS"
    local rule_name="Ensure rsyslog default file permissions are configured"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        # Skip if rsyslog not installed
        if ! command -v rsyslogd &> /dev/null; then
            log_warn "rsyslog not installed - skipping"
            ((PASSED_CHECKS++))
            return 0
        fi
        
        # Check both rsyslog.conf and drop-in files
        if grep -q '^\$FileCreateMode 0640' /etc/rsyslog.conf 2>/dev/null || \
           grep -rq '^\$FileCreateMode 0640' /etc/rsyslog.d/ 2>/dev/null; then
            log_pass "rsyslog file creation mode is configured (0640)"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "rsyslog file creation mode is not configured"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        # Check if rsyslog is installed first
        if ! command -v rsyslogd &> /dev/null; then
            log_warn "rsyslog is not installed - cannot configure file permissions"
            return 0
        fi
        
        # Check if rsyslog.conf exists
        if [ ! -f /etc/rsyslog.conf ]; then
            log_error "rsyslog.conf not found - rsyslog may not be properly installed"
            return 1
        fi
        
        # Create backup
        local backup_file="$BACKUP_DIR/rsyslog.conf.$(date +%Y%m%d_%H%M%S)"
        if cp /etc/rsyslog.conf "$backup_file" 2>/dev/null; then
            log_info "Created backup: $backup_file"
        else
            log_error "Failed to create backup of rsyslog.conf"
            return 1
        fi
        
        # Get current configuration
        local current_config=""
        if grep -q '^\$FileCreateMode' /etc/rsyslog.conf; then
            current_config=$(grep '^\$FileCreateMode' /etc/rsyslog.conf | head -1)
        else
            current_config="not_set"
        fi
        save_config "$rule_id" "$rule_name" "$current_config"
        
        # Apply configuration
        if grep -q '^\$FileCreateMode' /etc/rsyslog.conf; then
            # Setting exists - update it
            log_info "Updating existing FileCreateMode setting..."
            sed -i 's/^\$FileCreateMode.*/$FileCreateMode 0640/' /etc/rsyslog.conf
        else
            # Setting doesn't exist - add it
            log_info "Adding FileCreateMode setting..."
            
            # Find a good place to add it (after global directives, before rules)
            if grep -q '^#### GLOBAL DIRECTIVES' /etc/rsyslog.conf; then
                # Add after global directives section
                sed -i '/^#### GLOBAL DIRECTIVES/a\
\
# Set default permissions for log files\
$FileCreateMode 0640' /etc/rsyslog.conf
            else
                # Add at the beginning after comments
                sed -i '1a\
\
# Set default permissions for log files\
$FileCreateMode 0640' /etc/rsyslog.conf
            fi
        fi
        
        # Validate configuration
        log_info "Validating rsyslog configuration..."
        if rsyslogd -N1 &>/dev/null; then
            log_pass "rsyslog configuration is valid"
        else
            log_error "rsyslog configuration validation failed"
            log_error "Restoring backup..."
            cp "$backup_file" /etc/rsyslog.conf
            return 1
        fi
        
        # Restart rsyslog to apply changes
        log_info "Restarting rsyslog service..."
        if systemctl restart rsyslog 2>&1 | tee /tmp/rsyslog_restart.log; then
            log_pass "rsyslog restarted successfully"
            ((FIXED_CHECKS++))
            
            # Verify service is running
            sleep 1
            if systemctl is-active rsyslog 2>/dev/null | grep -q "active"; then
                log_pass "rsyslog is active and running"
            else
                log_error "rsyslog failed to start after restart"
                log_error "Check logs: journalctl -u rsyslog -n 50"
                return 1
            fi
        else
            log_error "Failed to restart rsyslog"
            log_error "Check /tmp/rsyslog_restart.log for details"
            log_error "Restoring backup configuration..."
            cp "$backup_file" /etc/rsyslog.conf
            systemctl restart rsyslog
            return 1
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        local backup=$(ls -t "$BACKUP_DIR"/rsyslog.conf.* 2>/dev/null | head -1)
        if [ -n "$backup" ]; then
            log_info "Restoring rsyslog configuration from: $backup"
            if cp "$backup" /etc/rsyslog.conf; then
                log_info "Configuration restored"
                
                # Validate before restarting
                if rsyslogd -N1 &>/dev/null; then
                    systemctl restart rsyslog
                    log_info "rsyslog restarted with original configuration"
                else
                    log_error "Restored configuration is invalid"
                fi
            else
                log_error "Failed to restore backup"
            fi
        else
            log_warn "No backup found to restore"
        fi
    fi
}

check_rsyslog_remote_logs() {
    local rule_id="LOG-RSYSLOG-REMOTE"
    local rule_name="Ensure rsyslog is configured to send logs to remote host"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        # Skip if rsyslog not installed
        if ! command -v rsyslogd &> /dev/null; then
            log_warn "rsyslog not installed - skipping remote logging check"
            ((PASSED_CHECKS++))
            return 0
        fi
        
        if grep -qE '^\*\.\*[[:space:]]+@' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null; then
            log_pass "rsyslog remote logging is configured"
            ((PASSED_CHECKS++))
            return 0
        else
            log_warn "rsyslog remote logging not configured (manual setup required)"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        # Skip if rsyslog not installed
        if ! command -v rsyslogd &> /dev/null; then
            log_warn "rsyslog not installed - cannot configure remote logging"
            return 0
        fi
        
        log_manual "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        log_manual "MANUAL CONFIGURATION REQUIRED: Remote Log Server"
        log_manual "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        log_manual "Remote logging requires a log server IP/hostname."
        log_manual ""
        log_manual "To configure remote logging:"
        log_manual "1. Determine your remote log server address"
        log_manual "2. Edit /etc/rsyslog.d/50-remote.conf"
        log_manual "3. Add one of these lines:"
        log_manual ""
        log_manual "   For UDP (standard):"
        log_manual "   *.* @logserver.example.com:514"
        log_manual ""
        log_manual "   For TCP (reliable):"
        log_manual "   *.* @@logserver.example.com:514"
        log_manual ""
        log_manual "4. Restart rsyslog:"
        log_manual "   sudo systemctl restart rsyslog"
        log_manual "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        ((MANUAL_CHECKS++))
        save_config "$rule_id" "$rule_name" "not_configured"
        
    elif [ "$MODE" = "rollback" ]; then
        log_info "Remote logging configuration requires manual rollback"
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
        else
            log_info "logrotate already installed"
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        log_info "logrotate configuration maintained"
    fi
}

check_logfile_permissions() {
    local rule_id="LOG-FILE-PERMS"
    local rule_name="Ensure permissions on all logfiles are configured"
    
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
        log_info "Fixed log file permissions (removed group write/execute and other read/write/execute)"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        log_warn "Log file permission rollback not recommended for security"
    fi
}

# ============================================================================
# 8.3 System Auditing - auditd
# ============================================================================

check_auditd_installed() {
    local rule_id="AUD-AUDITD-INSTALLED"
    local rule_name="Ensure auditd is installed"
    
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
            log_info "Installed auditd and plugins"
            ((FIXED_CHECKS++))
        else
            log_info "auditd already installed"
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
    local rule_name="Ensure auditd service is enabled and running"
    
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

check_auditd_boot_params() {
    local rule_id="AUD-BOOT-PARAMS"
    local rule_name="Ensure auditing for processes prior to auditd is enabled"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if grep -q "audit=1" /proc/cmdline 2>/dev/null; then
            log_pass "Boot parameter audit=1 is set"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "Boot parameter audit=1 is not set"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        log_manual "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        log_manual "MANUAL CONFIGURATION REQUIRED: GRUB Boot Parameters"
        log_manual "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        log_manual "To enable auditing from boot, you need to modify GRUB."
        log_manual ""
        log_manual "STEPS:"
        log_manual "1. Edit /etc/default/grub"
        log_manual "2. Find line: GRUB_CMDLINE_LINUX=\"...\""
        log_manual "3. Add 'audit=1' inside the quotes"
        log_manual "   Example: GRUB_CMDLINE_LINUX=\"quiet splash audit=1\""
        log_manual "4. Update GRUB:"
        log_manual "   sudo update-grub"
        log_manual "5. Reboot the system"
        log_manual ""
        log_manual "VERIFICATION:"
        log_manual "After reboot, verify with: grep audit=1 /proc/cmdline"
        log_manual "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        ((MANUAL_CHECKS++))
        save_config "$rule_id" "$rule_name" "not_set"
        
    elif [ "$MODE" = "rollback" ]; then
        log_manual "GRUB boot parameters require manual rollback"
        log_manual "Edit /etc/default/grub and remove 'audit=1', then run update-grub"
    fi
}

check_audit_backlog() {
    local rule_id="AUD-BACKLOG-LIMIT"
    local rule_name="Ensure audit_backlog_limit is sufficient"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        local backlog=$(grep -o "audit_backlog_limit=[0-9]*" /proc/cmdline 2>/dev/null | cut -d= -f2)
        
        if [ -n "$backlog" ] && [ "$backlog" -ge 8192 ]; then
            log_pass "audit_backlog_limit is sufficient ($backlog)"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "audit_backlog_limit not set or insufficient (current: ${backlog:-not set})"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        log_manual "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        log_manual "MANUAL CONFIGURATION REQUIRED: Audit Backlog Limit"
        log_manual "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        log_manual "Set audit_backlog_limit in GRUB for busy systems."
        log_manual ""
        log_manual "STEPS:"
        log_manual "1. Edit /etc/default/grub"
        log_manual "2. Find line: GRUB_CMDLINE_LINUX=\"...\""
        log_manual "3. Add 'audit_backlog_limit=8192' inside the quotes"
        log_manual "   Example: GRUB_CMDLINE_LINUX=\"quiet audit=1 audit_backlog_limit=8192\""
        log_manual "4. Update GRUB: sudo update-grub"
        log_manual "5. Reboot the system"
        log_manual "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        ((MANUAL_CHECKS++))
        save_config "$rule_id" "$rule_name" "not_set"
        
    elif [ "$MODE" = "rollback" ]; then
        log_manual "audit_backlog_limit requires manual rollback in GRUB"
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
            log_info "Configured audit log storage (10MB with keep_logs)"
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

check_audit_disk_full() {
    local rule_id="AUD-DISK-FULL"
    local rule_name="Ensure system is disabled when audit logs are full"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if [ -f /etc/audit/auditd.conf ]; then
            local space_left_action=$(grep "^space_left_action" /etc/audit/auditd.conf | awk '{print $3}')
            local action_mail_acct=$(grep "^action_mail_acct" /etc/audit/auditd.conf | awk '{print $3}')
            local admin_space_left_action=$(grep "^admin_space_left_action" /etc/audit/auditd.conf | awk '{print $3}')
            
            if [ "$space_left_action" = "email" ] && [ -n "$action_mail_acct" ] && [ "$admin_space_left_action" = "halt" ]; then
                log_pass "Audit disk full actions are properly configured"
                ((PASSED_CHECKS++))
                return 0
            else
                log_error "Audit disk full actions not properly configured"
                ((FAILED_CHECKS++))
                return 1
            fi
        fi
        
    elif [ "$MODE" = "fix" ]; then
        log_manual "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        log_manual "MANUAL CONFIGURATION REQUIRED: Audit Disk Full Actions"
        log_manual "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        log_manual "Configure what happens when audit logs fill the disk."
        log_manual ""
        log_manual "WARNING: admin_space_left_action = halt will HALT the system!"
        log_manual "This is CIS recommended but may not be suitable for all environments."
        log_manual ""
        log_manual "Edit /etc/audit/auditd.conf and configure:"
        log_manual "  space_left_action = email"
        log_manual "  action_mail_acct = root"
        log_manual "  admin_space_left_action = halt"
        log_manual ""
        log_manual "Alternative (less disruptive):"
        log_manual "  admin_space_left_action = single"
        log_manual ""
        log_manual "Then restart: sudo service auditd restart"
        log_manual "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        ((MANUAL_CHECKS++))
        save_config "$rule_id" "$rule_name" "not_configured"
        
    elif [ "$MODE" = "rollback" ]; then
        log_manual "Audit disk full actions require manual rollback"
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
## Audit Rules for System Hardening - CIS Benchmark Compliant

## Time changes (CIS 4.1.3)
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

## User/Group information changes (CIS 4.1.4)
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

## Network environment changes (CIS 4.1.5)
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/network -p wa -k system-locale
-w /etc/networks -p wa -k system-locale

## Mandatory Access Controls (MAC) (CIS 4.1.6)
-w /etc/selinux/ -p wa -k MAC-policy
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy

## Login/Logout events (CIS 4.1.7)
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins

## Session initiation (CIS 4.1.8)
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins

## Discretionary Access Control (DAC) modifications (CIS 4.1.9)
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod

## Unauthorized file access attempts (CIS 4.1.10)
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

## Privileged commands (CIS 4.1.11)
## Note: Add specific privileged commands for your system

## Successful file system mounts (CIS 4.1.12)
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts

## File deletion events (CIS 4.1.13)
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

## Sudoers changes (CIS 4.1.14)
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope

## Sudo command execution (CIS 4.1.15)
-a always,exit -F arch=b64 -C euid!=uid -F euid=0 -F auid>=1000 -F auid!=4294967295 -S execve -k actions
-a always,exit -F arch=b32 -C euid!=uid -F euid=0 -F auid>=1000 -F auid!=4294967295 -S execve -k actions

## Kernel module changes (CIS 4.1.16)
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

## Make audit configuration immutable (CIS 4.1.17)
## WARNING: This must be the last rule
## After setting this, you'll need to reboot to modify rules
# -e 2

EOF
        
        # Load rules
        augenrules --load
        log_info "Configured comprehensive audit rules"
        log_warn "Rule '-e 2' is commented out - uncomment to make rules immutable (requires reboot to change)"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        rm -f /etc/audit/rules.d/hardening.rules
        augenrules --load
        log_info "Removed custom audit rules"
    fi
}

check_audit_immutable() {
    local rule_id="AUD-IMMUTABLE"
    local rule_name="Ensure audit configuration is immutable"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if grep -q "^-e 2" /etc/audit/rules.d/*.rules 2>/dev/null; then
            log_pass "Audit configuration is set to immutable"
            ((PASSED_CHECKS++))
            return 0
        else
            log_warn "Audit configuration is not immutable"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        log_manual "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        log_manual "MANUAL DECISION REQUIRED: Audit Immutability"
        log_manual "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        log_manual "Making audit rules immutable prevents changes without reboot."
        log_manual ""
        log_manual "IMPLICATIONS:"
        log_manual "- Rules cannot be modified until system reboot"
        log_manual "- Provides additional security"
        log_manual "- May complicate troubleshooting"
        log_manual ""
        log_manual "TO ENABLE:"
        log_manual "1. Edit /etc/audit/rules.d/hardening.rules"
        log_manual "2. Uncomment the line: # -e 2"
        log_manual "3. Run: sudo augenrules --load"
        log_manual "4. Reboot to activate"
        log_manual ""
        log_manual "Current status: NOT immutable (can be changed without reboot)"
        log_manual "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        ((MANUAL_CHECKS++))
        save_config "$rule_id" "$rule_name" "not_immutable"
        
    elif [ "$MODE" = "rollback" ]; then
        log_manual "Audit immutability requires manual rollback"
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
            
            log_info "Installing AIDE (this may take several minutes)..."
            apt-get install -y aide aide-common
            
            log_info "Initializing AIDE database (this will take time)..."
            log_warn "Initial database creation can take 5-30 minutes depending on system size"
            
            if aideinit; then
                log_pass "AIDE installed and database initialized"
                ((FIXED_CHECKS++))
            else
                log_error "AIDE database initialization failed"
                return 1
            fi
        else
            log_info "AIDE already installed"
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        local original=$(get_original_config "$rule_id")
        if [ "$original" = "not_installed" ]; then
            apt-get remove -y aide aide-common
            rm -rf /var/lib/aide
            log_info "Removed AIDE and database"
        fi
    fi
}

check_aide_config() {
    local rule_id="AUD-AIDE-CONFIG"
    local rule_name="Ensure filesystem integrity is regularly checked"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        # Skip if AIDE not installed
        if ! command -v aide >/dev/null 2>&1; then
            log_warn "AIDE not installed - skipping"
            ((PASSED_CHECKS++))
            return 0
        fi
        
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
        # Skip if AIDE not installed
        if ! command -v aide >/dev/null 2>&1; then
            log_warn "AIDE not installed - cannot configure cron"
            return 0
        fi
        
        save_config "$rule_id" "$rule_name" "not_configured"
        
        # Create cron job for daily AIDE checks
        cat > /etc/cron.d/aide << 'EOF'
# Run AIDE integrity check daily at 5 AM
0 5 * * * root /usr/bin/aide.wrapper --config /etc/aide/aide.conf --check
EOF
        
        chmod 644 /etc/cron.d/aide
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
    echo "Logging and Auditing Hardening Script - Enhanced Version"
    echo "Mode: $MODE"
    echo "========================================================================"
    
    if [ "$MODE" = "scan" ] || [ "$MODE" = "fix" ]; then
        log_info "=== System Logging - journald ==="
        check_journald_enabled
        check_journald_compression
        check_journald_persistent
        
        log_info ""
        log_info "=== System Logging - rsyslog ==="
        check_rsyslog_installed
        check_rsyslog_enabled
        check_rsyslog_default_perms
        check_rsyslog_remote_logs
        check_logrotate
        check_logfile_permissions
        
        log_info ""
        log_info "=== System Auditing - auditd ==="
        check_auditd_installed
        check_auditd_enabled
        check_auditd_boot_params
        check_audit_backlog
        check_audit_log_storage
        check_audit_disk_full
        check_audit_rules
        check_audit_immutable
        
        log_info ""
        log_info "=== Integrity Checking - AIDE ==="
        check_aide_installed
        check_aide_config
        
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
            echo "Manual: $MANUAL_CHECKS"
            
            if [ $MANUAL_CHECKS -gt 0 ]; then
                log_warn "$MANUAL_CHECKS items require manual configuration"
                log_warn "Review the manual instructions above"
            fi
            
            log_info "Fixes applied. Run 'scan' mode to verify."
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        log_info "Rolling back logging and auditing configurations..."
        check_journald_compression
        check_journald_persistent
        check_rsyslog_enabled
        check_rsyslog_default_perms
        check_auditd_installed
        check_auditd_enabled
        check_audit_log_storage
        check_audit_rules
        check_aide_installed
        check_aide_config
        log_info "Rollback completed"
    else
        echo "Usage: $0 {scan|fix|rollback}"
        exit 1
    fi
}

main
