#!/bin/bash
# User Accounts and Environment Hardening Script
# Covers: Shadow Password Suite, Root Account, User Environment

MODE="${1:-scan}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="$SCRIPT_DIR/../hardening.db"
BACKUP_DIR="$SCRIPT_DIR/../backups/user_accounts"
TOPIC="User Accounts"

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
# 7.1 Shadow Password Suite Parameters
# ============================================================================

check_login_defs_param() {
    local param="$1"
    local expected_value="$2"
    local rule_id="USR-LOGINDEFS-$(echo $param | tr '[:lower:]' '[:upper:]')"
    local rule_name="Ensure $param is configured"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if [ -f /etc/login.defs ]; then
            local current=$(grep "^$param" /etc/login.defs | awk '{print $2}')
            
            if [ "$current" = "$expected_value" ] || [ "$current" -le "$expected_value" ] 2>/dev/null; then
                log_pass "$param is configured correctly"
                ((PASSED_CHECKS++))
                return 0
            else
                log_error "$param = $current (expected: $expected_value)"
                ((FAILED_CHECKS++))
                return 1
            fi
        else
            log_error "/etc/login.defs not found"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        if [ -f /etc/login.defs ]; then
            local current=$(grep "^$param" /etc/login.defs | awk '{print $2}')
            save_config "$rule_id" "$rule_name" "$current"
            
            cp /etc/login.defs "$BACKUP_DIR/login.defs.$(date +%Y%m%d_%H%M%S)"
            
            if grep -q "^$param" /etc/login.defs; then
                sed -i "s/^$param.*/$param\t$expected_value/" /etc/login.defs
            else
                echo "$param\t$expected_value" >> /etc/login.defs
            fi
            
            log_info "Set $param = $expected_value"
            ((FIXED_CHECKS++))
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        local backup=$(ls -t "$BACKUP_DIR"/login.defs.* 2>/dev/null | head -1)
        if [ -n "$backup" ]; then
            cp "$backup" /etc/login.defs
            log_info "Restored login.defs"
        fi
    fi
}

check_password_hashing() {
    local rule_id="USR-PASS-HASH"
    local rule_name="Ensure strong password hashing algorithm is configured"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        local encrypt_method=$(grep "^ENCRYPT_METHOD" /etc/login.defs | awk '{print $2}')
        
        if [ "$encrypt_method" = "SHA512" ] || [ "$encrypt_method" = "yescrypt" ]; then
            log_pass "Strong password hashing configured: $encrypt_method"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "Weak password hashing: $encrypt_method"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        local current=$(grep "^ENCRYPT_METHOD" /etc/login.defs | awk '{print $2}')
        save_config "$rule_id" "$rule_name" "$current"
        
        sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs
        log_info "Set password hashing to SHA512"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        local original=$(get_original_config "$rule_id")
        if [ -n "$original" ]; then
            sed -i "s/^ENCRYPT_METHOD.*/ENCRYPT_METHOD $original/" /etc/login.defs
            log_info "Restored password hashing algorithm"
        fi
    fi
}

check_inactive_password_lock() {
    local rule_id="USR-INACTIVE-LOCK"
    local rule_name="Ensure inactive password lock is configured"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        local inactive=$(useradd -D | grep INACTIVE | cut -d= -f2)
        
        if [ "$inactive" -le 30 ] && [ "$inactive" -gt 0 ] 2>/dev/null; then
            log_pass "Inactive password lock configured: $inactive days"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "Inactive password lock not configured: $inactive"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        local current=$(useradd -D | grep INACTIVE | cut -d= -f2)
        save_config "$rule_id" "$rule_name" "$current"
        
        useradd -D -f 30
        log_info "Set inactive password lock to 30 days"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        local original=$(get_original_config "$rule_id")
        if [ -n "$original" ]; then
            useradd -D -f "$original"
            log_info "Restored inactive password lock setting"
        fi
    fi
}

# ============================================================================
# 7.2 Root and System Accounts
# ============================================================================

check_root_uid_zero() {
    local rule_id="USR-ROOT-UID-ZERO"
    local rule_name="Ensure root is the only UID 0 account"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        local uid_zero_accounts=$(awk -F: '($3 == 0) { print $1 }' /etc/passwd)
        
        if [ "$uid_zero_accounts" = "root" ]; then
            log_pass "Only root has UID 0"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "Multiple UID 0 accounts found: $uid_zero_accounts"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        local other_uid_zero=$(awk -F: '($3 == 0 && $1 != "root") { print $1 }' /etc/passwd)
        
        if [ -n "$other_uid_zero" ]; then
            save_config "$rule_id" "$rule_name" "$other_uid_zero"
            log_warn "Found non-root UID 0 accounts: $other_uid_zero"
            log_warn "Manual intervention required - review these accounts"
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        log_info "Manual review required for UID 0 accounts"
    fi
}

check_root_gid_zero() {
    local rule_id="USR-ROOT-GID-ZERO"
    local rule_name="Ensure root is the only GID 0 account"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        local gid_zero_accounts=$(awk -F: '($4 == 0 && $1 != "root") { print $1 }' /etc/passwd)
        
        if [ -z "$gid_zero_accounts" ]; then
            log_pass "Only root has GID 0"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "Non-root accounts with GID 0: $gid_zero_accounts"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        local gid_zero=$(awk -F: '($4 == 0 && $1 != "root") { print $1 }' /etc/passwd)
        
        if [ -n "$gid_zero" ]; then
            save_config "$rule_id" "$rule_name" "$gid_zero"
            log_warn "Manual intervention required for accounts with GID 0: $gid_zero"
        fi
    fi
}

check_root_path() {
    local rule_id="USR-ROOT-PATH"
    local rule_name="Ensure root path integrity"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        local root_path=$(grep "^root:" /etc/passwd | cut -d: -f7)
        
        # Check for empty directories in PATH
        if echo "$PATH" | grep -q "::"; then
            log_error "Empty directory in root PATH"
            ((FAILED_CHECKS++))
            return 1
        fi
        
        # Check for trailing :
        if echo "$PATH" | grep -q ":$"; then
            log_error "Trailing : in root PATH"
            ((FAILED_CHECKS++))
            return 1
        fi
        
        # Check for . in PATH
        if echo "$PATH" | grep -q "\."; then
            log_error "Current directory (.) in root PATH"
            ((FAILED_CHECKS++))
            return 1
        fi
        
        log_pass "Root PATH integrity maintained"
        ((PASSED_CHECKS++))
        return 0
        
    elif [ "$MODE" = "fix" ]; then
        save_config "$rule_id" "$rule_name" "$PATH"
        log_warn "Manual review of root PATH required"
        log_info "Edit /root/.bashrc and /root/.profile to fix PATH"
        
    elif [ "$MODE" = "rollback" ]; then
        log_info "Manual PATH restoration required"
    fi
}

check_system_accounts_nologin() {
    local rule_id="USR-SYSTEM-NOLOGIN"
    local rule_name="Ensure system accounts do not have a valid login shell"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        local system_with_shell=$(awk -F: '($3 < 1000 && $1 != "root" && $7 !~ /nologin|false/) {print $1":"$7}' /etc/passwd)
        
        if [ -z "$system_with_shell" ]; then
            log_pass "System accounts have no valid login shell"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "System accounts with login shell found:"
            echo "$system_with_shell"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        local system_accounts=$(awk -F: '($3 < 1000 && $1 != "root" && $7 !~ /nologin|false/) {print $1}' /etc/passwd)
        
        if [ -n "$system_accounts" ]; then
            save_config "$rule_id" "$rule_name" "$system_accounts"
            
            for account in $system_accounts; do
                usermod -s /usr/sbin/nologin "$account"
                log_info "Set $account shell to /usr/sbin/nologin"
            done
            
            ((FIXED_CHECKS++))
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        local original=$(get_original_config "$rule_id")
        if [ -n "$original" ]; then
            log_warn "Manual restoration required for system account shells"
            log_info "Accounts affected: $original"
        fi
    fi
}

# ============================================================================
# 7.3 User Default Environment
# ============================================================================

check_default_umask() {
    local rule_id="USR-DEFAULT-UMASK"
    local rule_name="Ensure default user umask is configured"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        local umask_value=$(grep -h "^UMASK" /etc/login.defs 2>/dev/null | awk '{print $2}')
        
        if [ "$umask_value" = "027" ] || [ "$umask_value" = "077" ]; then
            log_pass "Default umask is properly configured: $umask_value"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "Default umask not properly configured: $umask_value"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        local current=$(grep "^UMASK" /etc/login.defs | awk '{print $2}')
        save_config "$rule_id" "$rule_name" "$current"
        
        sed -i 's/^UMASK.*/UMASK\t\t027/' /etc/login.defs
        
        # Also set in bashrc
        for file in /etc/bash.bashrc /etc/profile; do
            if [ -f "$file" ]; then
                if grep -q "^umask" "$file"; then
                    sed -i 's/^umask.*/umask 027/' "$file"
                else
                    echo "umask 027" >> "$file"
                fi
            fi
        done
        
        log_info "Set default umask to 027"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        local original=$(get_original_config "$rule_id")
        if [ -n "$original" ]; then
            sed -i "s/^UMASK.*/UMASK\t\t$original/" /etc/login.defs
            log_info "Restored default umask"
        fi
    fi
}

check_shell_timeout() {
    local rule_id="USR-SHELL-TIMEOUT"
    local rule_name="Ensure default user shell timeout is configured"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        local timeout_set=0
        
        for file in /etc/bash.bashrc /etc/profile /etc/profile.d/*.sh; do
            if [ -f "$file" ]; then
                if grep -q "^TMOUT=" "$file" 2>/dev/null; then
                    timeout_set=1
                    break
                fi
            fi
        done
        
        if [ $timeout_set -eq 1 ]; then
            log_pass "Shell timeout is configured"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "Shell timeout is not configured"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        save_config "$rule_id" "$rule_name" "not_configured"
        
        cat > /etc/profile.d/tmout.sh << 'EOF'
# Set shell timeout to 15 minutes
TMOUT=900
readonly TMOUT
export TMOUT
EOF
        
        chmod 644 /etc/profile.d/tmout.sh
        log_info "Configured shell timeout to 900 seconds (15 minutes)"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        rm -f /etc/profile.d/tmout.sh
        log_info "Removed shell timeout configuration"
    fi
}

# ============================================================================
# Main Execution
# ============================================================================

main() {
    echo "========================================================================"
    echo "User Accounts and Environment Hardening Script"
    echo "Mode: $MODE"
    echo "========================================================================"
    
    if [ "$MODE" = "scan" ] || [ "$MODE" = "fix" ]; then
        log_info "=== Shadow Password Suite ==="
        check_login_defs_param "PASS_MAX_DAYS" "365"
        check_login_defs_param "PASS_MIN_DAYS" "1"
        check_login_defs_param "PASS_WARN_AGE" "7"
        check_password_hashing
        check_inactive_password_lock
        
        log_info ""
        log_info "=== Root and System Accounts ==="
        check_root_uid_zero
        check_root_gid_zero
        check_root_path
        check_system_accounts_nologin
        
        log_info ""
        log_info "=== User Default Environment ==="
        check_default_umask
        check_shell_timeout
        
        echo ""
        echo "========================================================================"
        echo "Summary"
        echo "========================================================================"
        echo "Total Checks: $TOTAL_CHECKS"
        
        if [ "$MODE" = "scan" ]; then
            echo "Passed: $PASSED_CHECKS"
            echo "Failed: $FAILED_CHECKS"
            
            if [ $FAILED_CHECKS -eq 0 ]; then
                log_pass "All user account checks passed!"
            else
                log_warn "$FAILED_CHECKS checks failed. Run with 'fix' mode to remediate."
            fi
        else
            echo "Fixed: $FIXED_CHECKS"
            log_info "Fixes applied. Run 'scan' mode to verify."
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        log_info "Rolling back user account configurations..."
        check_login_defs_param "PASS_MAX_DAYS" ""
        check_password_hashing
        check_inactive_password_lock
        check_default_umask
        check_shell_timeout
        log_info "Rollback completed"
    else
        echo "Usage: $0 {scan|fix|rollback}"
        exit 1
    fi
}

main
