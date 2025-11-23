#!/bin/bash
# Network Hardening Script
# Covers: Network Devices, Kernel Modules, Kernel Parameters

MODE="${1:-scan}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="$SCRIPT_DIR/../hardening.db"
BACKUP_DIR="$SCRIPT_DIR/../backups/network"
TOPIC="Network"

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
# 4.1 Network Devices
# ============================================================================

check_wireless_disabled() {
    local rule_id="NET-DEV-WIRELESS"
    local rule_name="Ensure wireless interfaces are disabled"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        local wireless=$(ip link show | grep -E "wlan|wlp" | awk '{print $2}' | tr -d ':')
        
        if [ -z "$wireless" ]; then
            log_pass "No wireless interfaces found"
            ((PASSED_CHECKS++))
            return 0
        fi
        
        local active_wireless=""
        for iface in $wireless; do
            if ip link show "$iface" | grep -q "state UP"; then
                active_wireless="$active_wireless $iface"
            fi
        done
        
        if [ -n "$active_wireless" ]; then
            log_error "Active wireless interfaces:$active_wireless"
            ((FAILED_CHECKS++))
            return 1
        else
            log_pass "Wireless interfaces are disabled"
            ((PASSED_CHECKS++))
            return 0
        fi
        
    elif [ "$MODE" = "fix" ]; then
        local wireless=$(ip link show | grep -E "wlan|wlp" | awk '{print $2}' | tr -d ':')
        save_config "$rule_id" "$rule_name" "wireless_found"
        
        for iface in $wireless; do
            ip link set "$iface" down
            log_info "Disabled wireless interface: $iface"
        done
        
        # Disable wireless in NetworkManager
        if [ -f /etc/NetworkManager/NetworkManager.conf ]; then
            cp /etc/NetworkManager/NetworkManager.conf "$BACKUP_DIR/NetworkManager.conf.$(date +%Y%m%d_%H%M%S)"
            if ! grep -q "\\[keyfile\\]" /etc/NetworkManager/NetworkManager.conf; then
                echo -e "\n[keyfile]\nunmanaged-devices=interface-name:wlan*;interface-name:wlp*" >> /etc/NetworkManager/NetworkManager.conf
            fi
        fi
        
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        local backup=$(ls -t "$BACKUP_DIR"/NetworkManager.conf.* 2>/dev/null | head -1)
        if [ -n "$backup" ]; then
            cp "$backup" /etc/NetworkManager/NetworkManager.conf
            systemctl restart NetworkManager 2>/dev/null
            log_info "Restored NetworkManager configuration"
        fi
    fi
}

check_bluetooth_disabled() {
    local rule_id="NET-DEV-BLUETOOTH"
    local rule_name="Ensure bluetooth services are not in use"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if systemctl is-enabled bluetooth 2>/dev/null | grep -q "enabled"; then
            log_error "Bluetooth service is enabled"
            ((FAILED_CHECKS++))
            return 1
        elif systemctl is-active bluetooth 2>/dev/null | grep -q "active"; then
            log_error "Bluetooth service is active"
            ((FAILED_CHECKS++))
            return 1
        else
            log_pass "Bluetooth is disabled"
            ((PASSED_CHECKS++))
            return 0
        fi
        
    elif [ "$MODE" = "fix" ]; then
        local was_enabled="no"
        if systemctl is-enabled bluetooth 2>/dev/null | grep -q "enabled"; then
            was_enabled="yes"
        fi
        
        save_config "$rule_id" "$rule_name" "enabled=$was_enabled"
        
        systemctl stop bluetooth 2>/dev/null
        systemctl disable bluetooth 2>/dev/null
        systemctl mask bluetooth 2>/dev/null
        log_info "Disabled bluetooth service"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        local original=$(get_original_config "$rule_id")
        if echo "$original" | grep -q "enabled=yes"; then
            systemctl unmask bluetooth 2>/dev/null
            systemctl enable bluetooth 2>/dev/null
            systemctl start bluetooth 2>/dev/null
            log_info "Re-enabled bluetooth service"
        fi
    fi
}

# ============================================================================
# 4.2 Network Kernel Modules
# ============================================================================

check_network_module() {
    local module="$1"
    local rule_id="NET-MOD-$(echo $module | tr '[:lower:]' '[:upper:]')"
    local rule_name="Ensure $module kernel module is not available"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if lsmod | grep -q "^$module "; then
            log_error "Module $module is loaded"
            ((FAILED_CHECKS++))
            return 1
        fi
        
        if grep -rq "install $module /bin/true" /etc/modprobe.d/; then
            log_pass "Module $module is blacklisted"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "Module $module is not blacklisted"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        save_config "$rule_id" "$rule_name" "not_blacklisted"
        
        echo "install $module /bin/true" > "/etc/modprobe.d/$module-blacklist.conf"
        echo "blacklist $module" >> "/etc/modprobe.d/$module-blacklist.conf"
        
        if lsmod | grep -q "^$module "; then
            rmmod "$module" 2>/dev/null || modprobe -r "$module" 2>/dev/null
        fi
        
        log_info "Blacklisted module: $module"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        rm -f "/etc/modprobe.d/$module-blacklist.conf"
        log_info "Removed blacklist for $module"
    fi
}

# ============================================================================
# 4.3 Network Kernel Parameters
# ============================================================================

check_sysctl_param() {
    local param="$1"
    local expected_value="$2"
    local rule_id="NET-SYSCTL-$(echo $param | tr '.' '_' | tr '[:lower:]' '[:upper:]')"
    local rule_name="Ensure $param is set to $expected_value"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        local current_value=$(sysctl -n "$param" 2>/dev/null)
        
        if [ "$current_value" = "$expected_value" ]; then
            log_pass "$param = $expected_value"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "$param = $current_value (expected: $expected_value)"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        local current=$(sysctl -n "$param" 2>/dev/null)
        save_config "$rule_id" "$rule_name" "$current"
        
        # Set runtime
        sysctl -w "$param=$expected_value" >/dev/null 2>&1
        
        # Set persistent
        local sysctl_file="/etc/sysctl.d/99-hardening.conf"
        
        if grep -q "^$param" "$sysctl_file" 2>/dev/null; then
            sed -i "s|^$param.*|$param = $expected_value|" "$sysctl_file"
        else
            echo "$param = $expected_value" >> "$sysctl_file"
        fi
        
        log_info "Set $param = $expected_value"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        local original=$(get_original_config "$rule_id")
        if [ -n "$original" ]; then
            sysctl -w "$param=$original" >/dev/null 2>&1
            log_info "Restored $param = $original"
        fi
    fi
}

# ============================================================================
# Main Execution
# ============================================================================

main() {
    echo "========================================================================"
    echo "Network Hardening Script"
    echo "Mode: $MODE"
    echo "========================================================================"
    
    if [ "$MODE" = "scan" ] || [ "$MODE" = "fix" ]; then
        log_info "=== Network Devices ==="
        check_wireless_disabled
        check_bluetooth_disabled
        
        log_info ""
        log_info "=== Network Kernel Modules ==="
        check_network_module "dccp"
        check_network_module "tipc"
        check_network_module "rds"
        check_network_module "sctp"
        
        log_info ""
        log_info "=== Network Kernel Parameters ==="
        
        # IP Forwarding
        check_sysctl_param "net.ipv4.ip_forward" "0"
        check_sysctl_param "net.ipv6.conf.all.forwarding" "0"
        
        # Packet Redirect Sending
        check_sysctl_param "net.ipv4.conf.all.send_redirects" "0"
        check_sysctl_param "net.ipv4.conf.default.send_redirects" "0"
        
        # Source Routed Packets
        check_sysctl_param "net.ipv4.conf.all.accept_source_route" "0"
        check_sysctl_param "net.ipv4.conf.default.accept_source_route" "0"
        check_sysctl_param "net.ipv6.conf.all.accept_source_route" "0"
        check_sysctl_param "net.ipv6.conf.default.accept_source_route" "0"
        
        # ICMP Redirects
        check_sysctl_param "net.ipv4.conf.all.accept_redirects" "0"
        check_sysctl_param "net.ipv4.conf.default.accept_redirects" "0"
        check_sysctl_param "net.ipv6.conf.all.accept_redirects" "0"
        check_sysctl_param "net.ipv6.conf.default.accept_redirects" "0"
        
        # Secure ICMP Redirects
        check_sysctl_param "net.ipv4.conf.all.secure_redirects" "0"
        check_sysctl_param "net.ipv4.conf.default.secure_redirects" "0"
        
        # Log Suspicious Packets
        check_sysctl_param "net.ipv4.conf.all.log_martians" "1"
        check_sysctl_param "net.ipv4.conf.default.log_martians" "1"
        
        # Ignore Broadcast ICMP
        check_sysctl_param "net.ipv4.icmp_echo_ignore_broadcasts" "1"
        
        # Ignore Bogus ICMP Responses
        check_sysctl_param "net.ipv4.icmp_ignore_bogus_error_responses" "1"
        
        # Reverse Path Filtering
        check_sysctl_param "net.ipv4.conf.all.rp_filter" "1"
        check_sysctl_param "net.ipv4.conf.default.rp_filter" "1"
        
        # TCP SYN Cookies
        check_sysctl_param "net.ipv4.tcp_syncookies" "1"
        
        # IPv6 Router Advertisements
        check_sysctl_param "net.ipv6.conf.all.accept_ra" "0"
        check_sysctl_param "net.ipv6.conf.default.accept_ra" "0"
        
        echo ""
        echo "========================================================================"
        echo "Summary"
        echo "========================================================================"
        echo "Total Checks: $TOTAL_CHECKS"
        
        if [ "$MODE" = "scan" ]; then
            echo "Passed: $PASSED_CHECKS"
            echo "Failed: $FAILED_CHECKS"
            
            if [ $FAILED_CHECKS -eq 0 ]; then
                log_pass "All network checks passed!"
            else
                log_warn "$FAILED_CHECKS checks failed. Run with 'fix' mode to remediate."
            fi
        else
            echo "Fixed: $FIXED_CHECKS"
            log_info "Fixes applied. Run 'scan' mode to verify."
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        log_info "Rolling back network configurations..."
        
        # Rollback would restore original sysctl values
        local sysctl_backup="/etc/sysctl.d/99-hardening.conf.backup"
        if [ -f "$sysctl_backup" ]; then
            cp "$sysctl_backup" /etc/sysctl.d/99-hardening.conf
            sysctl -p /etc/sysctl.d/99-hardening.conf
        fi
        
        log_info "Rollback completed"
    else
        echo "Usage: $0 {scan|fix|rollback}"
        exit 1
    fi
}

main
