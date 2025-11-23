#!/bin/bash
# Host Based Firewall Hardening Script
# Covers: UFW Configuration

MODE="${1:-scan}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="$SCRIPT_DIR/../hardening.db"
BACKUP_DIR="$SCRIPT_DIR/../backups/firewall"
TOPIC="Host Based Firewall"

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
# 5.1 UFW Configuration
# ============================================================================

check_ufw_installed() {
    local rule_id="FW-UFW-INSTALLED"
    local rule_name="Ensure ufw is installed"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if dpkg -l | grep -q "^ii.*ufw"; then
            log_pass "UFW is installed"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "UFW is not installed"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        if ! dpkg -l | grep -q "^ii.*ufw"; then
            save_config "$rule_id" "$rule_name" "not_installed"
            apt-get update
            apt-get install -y ufw
            log_info "Installed UFW"
            ((FIXED_CHECKS++))
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        local original=$(get_original_config "$rule_id")
        if [ "$original" = "not_installed" ]; then
            apt-get remove -y ufw
            log_info "Removed UFW"
        fi
    fi
}

check_iptables_persistent() {
    local rule_id="FW-IPTABLES-NOT-INSTALLED"
    local rule_name="Ensure iptables-persistent is not installed with ufw"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if dpkg -l | grep -q "^ii.*iptables-persistent"; then
            log_error "iptables-persistent is installed (conflicts with UFW)"
            ((FAILED_CHECKS++))
            return 1
        else
            log_pass "iptables-persistent is not installed"
            ((PASSED_CHECKS++))
            return 0
        fi
        
    elif [ "$MODE" = "fix" ]; then
        if dpkg -l | grep -q "^ii.*iptables-persistent"; then
            save_config "$rule_id" "$rule_name" "installed"
            apt-get remove -y iptables-persistent
            log_info "Removed iptables-persistent"
            ((FIXED_CHECKS++))
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        local original=$(get_original_config "$rule_id")
        if [ "$original" = "installed" ]; then
            apt-get install -y iptables-persistent
            log_info "Reinstalled iptables-persistent"
        fi
    fi
}

check_ufw_enabled() {
    local rule_id="FW-UFW-ENABLED"
    local rule_name="Ensure ufw service is enabled"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if ufw status | grep -q "Status: active"; then
            log_pass "UFW is enabled and active"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "UFW is not enabled"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        local status=$(ufw status 2>/dev/null | grep "Status:" | awk '{print $2}')
        save_config "$rule_id" "$rule_name" "$status"
        
        # Enable UFW with automatic 'yes' to prompt
        echo "y" | ufw enable
        systemctl enable ufw
        log_info "Enabled UFW"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        local original=$(get_original_config "$rule_id")
        if [ "$original" = "inactive" ]; then
            ufw disable
            log_info "Disabled UFW"
        fi
    fi
}

check_ufw_loopback() {
    local rule_id="FW-UFW-LOOPBACK"
    local rule_name="Ensure ufw loopback traffic is configured"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        local lo_allow_in=$(ufw status verbose | grep -c "Anywhere on lo.*ALLOW IN")
        local lo_deny_in=$(ufw status verbose | grep -c "Anywhere.*DENY IN.*127.0.0.0/8")
        
        if [ "$lo_allow_in" -gt 0 ] && [ "$lo_deny_in" -gt 0 ]; then
            log_pass "UFW loopback traffic is configured"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "UFW loopback traffic not properly configured"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        save_config "$rule_id" "$rule_name" "not_configured"
        
        ufw allow in on lo
        ufw allow out on lo
        ufw deny in from 127.0.0.0/8
        ufw deny in from ::1
        
        log_info "Configured UFW loopback traffic"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        ufw delete allow in on lo 2>/dev/null
        ufw delete allow out on lo 2>/dev/null
        ufw delete deny in from 127.0.0.0/8 2>/dev/null
        ufw delete deny in from ::1 2>/dev/null
        log_info "Removed UFW loopback rules"
    fi
}

check_ufw_default_deny() {
    local rule_id="FW-UFW-DEFAULT-DENY"
    local rule_name="Ensure ufw default deny firewall policy"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        local default_incoming=$(ufw status verbose | grep "Default:" | grep -o "deny (incoming)" | wc -l)
        local default_outgoing=$(ufw status verbose | grep "Default:" | grep -E "allow \(outgoing\)|deny \(outgoing\)" | wc -l)
        
        if [ "$default_incoming" -gt 0 ]; then
            log_pass "UFW default deny policy is set"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "UFW default deny policy not set"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        save_config "$rule_id" "$rule_name" "not_configured"
        
        ufw default deny incoming
        ufw default deny outgoing
        ufw default deny routed
        
        log_info "Set UFW default deny policy"
        log_warn "You may need to explicitly allow required outgoing connections"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        ufw default allow outgoing
        log_info "Restored UFW default outgoing policy"
    fi
}

check_ufw_open_ports() {
    local rule_id="FW-UFW-OPEN-PORTS"
    local rule_name="Ensure ufw firewall rules exist for all open ports"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        # Get listening ports
        local listening_ports=$(ss -tuln | grep LISTEN | awk '{print $5}' | sed 's/.*://' | sort -u)
        local uncovered_ports=""
        
        for port in $listening_ports; do
            if [ "$port" = "Port" ]; then
                continue
            fi
            
            if ! ufw status | grep -qE "$port.*ALLOW"; then
                uncovered_ports="$uncovered_ports $port"
            fi
        done
        
        if [ -z "$uncovered_ports" ]; then
            log_pass "All open ports have UFW rules"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "Open ports without UFW rules:$uncovered_ports"
            log_warn "Run 'ss -tuln' to see all listening ports"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        save_config "$rule_id" "$rule_name" "manual_review_required"
        log_warn "Manual review required - add rules for required services"
        log_info "Example: ufw allow 22/tcp  # for SSH"
        log_info "Example: ufw allow 80/tcp  # for HTTP"
        log_info "Example: ufw allow 443/tcp # for HTTPS"
        
    elif [ "$MODE" = "rollback" ]; then
        log_info "Manual review of firewall rules recommended"
    fi
}

# ============================================================================
# Main Execution
# ============================================================================

main() {
    echo "========================================================================"
    echo "Host Based Firewall Hardening Script"
    echo "Mode: $MODE"
    echo "========================================================================"
    
    if [ "$MODE" = "scan" ] || [ "$MODE" = "fix" ]; then
        log_info "=== UFW Configuration ==="
        check_ufw_installed
        check_iptables_persistent
        check_ufw_enabled
        check_ufw_loopback
        check_ufw_default_deny
        check_ufw_open_ports
        
        echo ""
        echo "========================================================================"
        echo "Summary"
        echo "========================================================================"
        echo "Total Checks: $TOTAL_CHECKS"
        
        if [ "$MODE" = "scan" ]; then
            echo "Passed: $PASSED_CHECKS"
            echo "Failed: $FAILED_CHECKS"
            
            if [ $FAILED_CHECKS -eq 0 ]; then
                log_pass "All firewall checks passed!"
            else
                log_warn "$FAILED_CHECKS checks failed. Run with 'fix' mode to remediate."
            fi
        else
            echo "Fixed: $FIXED_CHECKS"
            log_info "Fixes applied. Run 'scan' mode to verify."
            log_warn "Important: Review and configure firewall rules for your required services"
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        log_info "Rolling back firewall configurations..."
        
        check_ufw_installed
        check_iptables_persistent
        check_ufw_enabled
        check_ufw_loopback
        check_ufw_default_deny
        
        log_info "Rollback completed"
    else
        echo "Usage: $0 {scan|fix|rollback}"
        exit 1
    fi
}

main
