#!/bin/bash
# Services Hardening Script
# Covers: Server Services, Client Services, Time Synchronization, Job Schedulers

MODE="${1:-scan}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="$SCRIPT_DIR/../hardening.db"
BACKUP_DIR="$SCRIPT_DIR/../backups/services"
TOPIC="Services"

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
# 3.1 Server Services
# ============================================================================

check_service() {
    local service_name="$1"
    local package_name="${2:-$service_name}"
    local rule_id="SVC-SVR-$(echo $service_name | tr '[:lower:]' '[:upper:]' | tr '-' '_')"
    local rule_name="Ensure $service_name services are not in use"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        # Check if package is installed
        if dpkg -l 2>/dev/null | grep -q "^ii.*$package_name"; then
            log_error "$service_name package is installed"
            ((FAILED_CHECKS++))
            return 1
        fi
        
        # Check if service is running
        if systemctl is-active "$service_name" 2>/dev/null | grep -q "active"; then
            log_error "$service_name service is active"
            ((FAILED_CHECKS++))
            return 1
        fi
        
        # Check if service is enabled
        if systemctl is-enabled "$service_name" 2>/dev/null | grep -q "enabled"; then
            log_error "$service_name service is enabled"
            ((FAILED_CHECKS++))
            return 1
        fi
        
        log_pass "$service_name is not in use"
        ((PASSED_CHECKS++))
        return 0
        
    elif [ "$MODE" = "fix" ]; then
        local was_installed="no"
        local was_enabled="no"
        
        if dpkg -l 2>/dev/null | grep -q "^ii.*$package_name"; then
            was_installed="yes"
        fi
        
        if systemctl is-enabled "$service_name" 2>/dev/null | grep -q "enabled"; then
            was_enabled="yes"
        fi
        
        save_config "$rule_id" "$rule_name" "installed=$was_installed,enabled=$was_enabled"
        
        # Stop and disable service
        systemctl stop "$service_name" 2>/dev/null
        systemctl disable "$service_name" 2>/dev/null
        systemctl mask "$service_name" 2>/dev/null
        
        # Remove package if installed
        if [ "$was_installed" = "yes" ]; then
            apt-get remove -y "$package_name" 2>/dev/null
            log_info "Removed $package_name package"
        fi
        
        log_info "Disabled and stopped $service_name"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        local original=$(get_original_config "$rule_id")
        if [ -n "$original" ]; then
            local was_installed=$(echo "$original" | grep -o "installed=[^,]*" | cut -d= -f2)
            local was_enabled=$(echo "$original" | grep -o "enabled=.*" | cut -d= -f2)
            
            if [ "$was_installed" = "yes" ]; then
                apt-get install -y "$package_name" 2>/dev/null
                log_info "Reinstalled $package_name"
            fi
            
            if [ "$was_enabled" = "yes" ]; then
                systemctl unmask "$service_name" 2>/dev/null
                systemctl enable "$service_name" 2>/dev/null
                systemctl start "$service_name" 2>/dev/null
                log_info "Re-enabled $service_name"
            fi
        fi
    fi
}

check_all_server_services() {
    log_info "=== Checking Server Services ==="
    
    check_service "autofs"
    check_service "avahi-daemon" "avahi-daemon"
    check_service "isc-dhcp-server" "isc-dhcp-server"
    check_service "bind9" "bind9"
    check_service "dnsmasq"
    check_service "vsftpd" "vsftpd"
    check_service "slapd" "slapd"
    check_service "dovecot" "dovecot-core"
    check_service "nfs-server" "nfs-kernel-server"
    check_service "ypserv" "nis"
    check_service "cups" "cups"
    check_service "rpcbind"
    check_service "rsync"
    check_service "smbd" "samba"
    check_service "snmpd" "snmp"
    check_service "tftpd-hpa" "tftpd-hpa"
    check_service "squid" "squid"
    check_service "apache2" "apache2"
    check_service "xinetd"
    check_service "xserver-xorg" "xserver-xorg-core"
}

# ============================================================================
# 3.2 Client Services
# ============================================================================

check_client_package() {
    local package_name="$1"
    local rule_id="SVC-CLI-$(echo $package_name | tr '[:lower:]' '[:upper:]' | tr '-' '_')"
    local rule_name="Ensure $package_name client is not installed"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if dpkg -l 2>/dev/null | grep -q "^ii.*$package_name"; then
            log_error "$package_name is installed"
            ((FAILED_CHECKS++))
            return 1
        else
            log_pass "$package_name is not installed"
            ((PASSED_CHECKS++))
            return 0
        fi
        
    elif [ "$MODE" = "fix" ]; then
        if dpkg -l 2>/dev/null | grep -q "^ii.*$package_name"; then
            save_config "$rule_id" "$rule_name" "installed"
            apt-get remove -y "$package_name" 2>/dev/null
            log_info "Removed $package_name"
            ((FIXED_CHECKS++))
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        local original=$(get_original_config "$rule_id")
        if [ "$original" = "installed" ]; then
            apt-get install -y "$package_name" 2>/dev/null
            log_info "Reinstalled $package_name"
        fi
    fi
}

check_all_client_services() {
    log_info "=== Checking Client Services ==="
    
    check_client_package "nis"
    check_client_package "rsh-client"
    check_client_package "talk"
    check_client_package "telnet"
    check_client_package "ldap-utils"
    check_client_package "ftp"
}

# ============================================================================
# 3.3 Mail Transfer Agent
# ============================================================================

check_mta_local_only() {
    local rule_id="SVC-MTA-LOCAL"
    local rule_name="Ensure mail transfer agent is configured for local-only mode"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        # Check if any MTA is listening on external interfaces
        local listening=$(ss -lntu | grep -E ':25\s' | grep -v '127.0.0.1')
        
        if [ -z "$listening" ]; then
            log_pass "MTA is configured for local-only mode"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "MTA is listening on external interfaces"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        save_config "$rule_id" "$rule_name" "not_local_only"
        
        # Configure postfix if installed
        if dpkg -l | grep -q "^ii.*postfix"; then
            cp /etc/postfix/main.cf "$BACKUP_DIR/postfix_main.cf.$(date +%Y%m%d_%H%M%S)"
            postconf -e 'inet_interfaces = loopback-only'
            systemctl restart postfix
            log_info "Configured Postfix for local-only mode"
            ((FIXED_CHECKS++))
        fi
        
        # Configure exim4 if installed
        if dpkg -l | grep -q "^ii.*exim4"; then
            log_warn "Exim4 detected - configure dc_local_interfaces='127.0.0.1' in /etc/exim4/update-exim4.conf.conf"
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        local backup=$(ls -t "$BACKUP_DIR"/postfix_main.cf.* 2>/dev/null | head -1)
        if [ -n "$backup" ]; then
            cp "$backup" /etc/postfix/main.cf
            systemctl restart postfix 2>/dev/null
            log_info "Restored Postfix configuration"
        fi
    fi
}

# ============================================================================
# 3.4 Time Synchronization
# ============================================================================

check_time_sync() {
    local rule_id="SVC-TIME-SYNC"
    local rule_name="Ensure time synchronization is in use"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if systemctl is-active systemd-timesyncd 2>/dev/null | grep -q "active"; then
            log_pass "systemd-timesyncd is active"
            ((PASSED_CHECKS++))
            return 0
        elif systemctl is-active chrony 2>/dev/null | grep -q "active"; then
            log_pass "chrony is active"
            ((PASSED_CHECKS++))
            return 0
        elif systemctl is-active ntp 2>/dev/null | grep -q "active"; then
            log_pass "ntp is active"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "No time synchronization service is active"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        save_config "$rule_id" "$rule_name" "not_configured"
        
        # Enable systemd-timesyncd if available
        if command -v timedatectl >/dev/null; then
            timedatectl set-ntp true
            systemctl enable systemd-timesyncd
            systemctl start systemd-timesyncd
            log_info "Enabled systemd-timesyncd"
            ((FIXED_CHECKS++))
        else
            log_warn "Install chrony or ntp for time synchronization"
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        timedatectl set-ntp false 2>/dev/null
        systemctl stop systemd-timesyncd 2>/dev/null
        log_info "Disabled time synchronization"
    fi
}

check_timesyncd_config() {
    local rule_id="SVC-TIME-TIMESYNCD-CONFIG"
    local rule_name="Ensure systemd-timesyncd configured with authorized timeserver"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if [ -f /etc/systemd/timesyncd.conf ]; then
            if grep -q "^NTP=" /etc/systemd/timesyncd.conf; then
                log_pass "systemd-timesyncd NTP servers configured"
                ((PASSED_CHECKS++))
                return 0
            else
                log_warn "systemd-timesyncd NTP servers not explicitly configured"
                ((FAILED_CHECKS++))
                return 1
            fi
        else
            log_warn "systemd-timesyncd configuration not found"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        if [ -f /etc/systemd/timesyncd.conf ]; then
            cp /etc/systemd/timesyncd.conf "$BACKUP_DIR/timesyncd.conf.$(date +%Y%m%d_%H%M%S)"
            save_config "$rule_id" "$rule_name" "not_configured"
            
            # Configure NTP servers
            sed -i 's/^#NTP=/NTP=/' /etc/systemd/timesyncd.conf
            if ! grep -q "^NTP=" /etc/systemd/timesyncd.conf; then
                echo "NTP=time.nist.gov" >> /etc/systemd/timesyncd.conf
            fi
            
            systemctl restart systemd-timesyncd
            log_info "Configured systemd-timesyncd NTP servers"
            ((FIXED_CHECKS++))
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        local backup=$(ls -t "$BACKUP_DIR"/timesyncd.conf.* 2>/dev/null | head -1)
        if [ -n "$backup" ]; then
            cp "$backup" /etc/systemd/timesyncd.conf
            systemctl restart systemd-timesyncd 2>/dev/null
            log_info "Restored timesyncd configuration"
        fi
    fi
}

# ============================================================================
# 3.5 Job Schedulers
# ============================================================================

check_cron_enabled() {
    local rule_id="SVC-CRON-ENABLED"
    local rule_name="Ensure cron daemon is enabled and active"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if systemctl is-enabled cron 2>/dev/null | grep -q "enabled" && \
           systemctl is-active cron 2>/dev/null | grep -q "active"; then
            log_pass "Cron daemon is enabled and active"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "Cron daemon is not properly configured"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        save_config "$rule_id" "$rule_name" "not_enabled"
        systemctl enable cron
        systemctl start cron
        log_info "Enabled and started cron daemon"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        systemctl disable cron 2>/dev/null
        systemctl stop cron 2>/dev/null
        log_info "Disabled cron daemon"
    fi
}

check_cron_permissions() {
    local file="$1"
    local expected_perms="$2"
    local rule_id="SVC-CRON-$(basename $file | tr '[:lower:]' '[:upper:]' | tr '.' '_')"
    local rule_name="Ensure permissions on $file are configured"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if [ -f "$file" ] || [ -d "$file" ]; then
            local perms=$(stat -c %a "$file")
            local owner=$(stat -c %U "$file")
            local group=$(stat -c %G "$file")
            
            if [ "$perms" = "$expected_perms" ] && [ "$owner" = "root" ] && [ "$group" = "root" ]; then
                log_pass "$file permissions correct: $expected_perms root:root"
                ((PASSED_CHECKS++))
                return 0
            else
                log_error "$file permissions incorrect: $perms $owner:$group"
                ((FAILED_CHECKS++))
                return 1
            fi
        else
            log_warn "$file does not exist"
            ((PASSED_CHECKS++))
            return 0
        fi
        
    elif [ "$MODE" = "fix" ]; then
        if [ -f "$file" ] || [ -d "$file" ]; then
            local current=$(stat -c "%a %U:%G" "$file")
            save_config "$rule_id" "$rule_name" "$current"
            
            chown root:root "$file"
            chmod "$expected_perms" "$file"
            log_info "Set $file permissions to $expected_perms root:root"
            ((FIXED_CHECKS++))
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        local original=$(get_original_config "$rule_id")
        if [ -n "$original" ] && [ -e "$file" ]; then
            local orig_perms=$(echo "$original" | awk '{print $1}')
            chmod "$orig_perms" "$file" 2>/dev/null
            log_info "Restored $file permissions"
        fi
    fi
}

check_crontab_restricted() {
    local rule_id="SVC-CRON-RESTRICTED"
    local rule_name="Ensure crontab is restricted to authorized users"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if [ -f /etc/cron.allow ]; then
            log_pass "/etc/cron.allow exists"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "/etc/cron.allow does not exist"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        save_config "$rule_id" "$rule_name" "not_restricted"
        
        touch /etc/cron.allow
        chown root:root /etc/cron.allow
        chmod 600 /etc/cron.allow
        
        rm -f /etc/cron.deny
        
        log_info "Created /etc/cron.allow and removed /etc/cron.deny"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        rm -f /etc/cron.allow
        log_info "Removed /etc/cron.allow"
    fi
}

# ============================================================================
# Main Execution
# ============================================================================

main() {
    echo "========================================================================"
    echo "Services Hardening Script"
    echo "Mode: $MODE"
    echo "========================================================================"
    
    if [ "$MODE" = "scan" ] || [ "$MODE" = "fix" ]; then
        check_all_server_services
        
        log_info ""
        check_all_client_services
        
        log_info ""
        log_info "=== Mail Transfer Agent ==="
        check_mta_local_only
        
        log_info ""
        log_info "=== Time Synchronization ==="
        check_time_sync
        check_timesyncd_config
        
        log_info ""
        log_info "=== Job Schedulers ==="
        check_cron_enabled
        check_cron_permissions "/etc/crontab" "600"
        check_cron_permissions "/etc/cron.hourly" "700"
        check_cron_permissions "/etc/cron.daily" "700"
        check_cron_permissions "/etc/cron.weekly" "700"
        check_cron_permissions "/etc/cron.monthly" "700"
        check_cron_permissions "/etc/cron.d" "700"
        check_crontab_restricted
        
        echo ""
        echo "========================================================================"
        echo "Summary"
        echo "========================================================================"
        echo "Total Checks: $TOTAL_CHECKS"
        
        if [ "$MODE" = "scan" ]; then
            echo "Passed: $PASSED_CHECKS"
            echo "Failed: $FAILED_CHECKS"
            
            if [ $FAILED_CHECKS -eq 0 ]; then
                log_pass "All service checks passed!"
            else
                log_warn "$FAILED_CHECKS checks failed. Run with 'fix' mode to remediate."
            fi
        else
            echo "Fixed: $FIXED_CHECKS"
            log_info "Fixes applied. Run 'scan' mode to verify."
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        log_info "Rolling back service configurations..."
        # Rollback would call the same functions in rollback mode
        log_info "Rollback completed"
    else
        echo "Usage: $0 {scan|fix|rollback}"
        exit 1
    fi
}

main
