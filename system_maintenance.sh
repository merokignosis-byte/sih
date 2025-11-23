#!/bin/bash
# System Maintenance Hardening Script
# Covers: File Permissions, Duplicate Checks, User/Group Settings

MODE="${1:-scan}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="$SCRIPT_DIR/../hardening.db"
BACKUP_DIR="$SCRIPT_DIR/../backups/system_maintenance"
TOPIC="System Maintenance"

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
# 9.1 System File Permissions
# ============================================================================

check_file_permissions() {
    local file="$1"
    local expected_perms="$2"
    local expected_owner="${3:-root}"
    local expected_group="${4:-root}"
    local rule_id="SYS-PERM-$(echo $file | tr '/' '-' | tr '.' '_' | tr '[:lower:]' '[:upper:]')"
    local rule_name="Ensure permissions on $file are configured"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if [ ! -f "$file" ] && [ ! -d "$file" ]; then
            log_warn "$file does not exist"
            ((PASSED_CHECKS++))
            return 0
        fi
        
        local perms=$(stat -c %a "$file" 2>/dev/null)
        local owner=$(stat -c %U "$file" 2>/dev/null)
        local group=$(stat -c %G "$file" 2>/dev/null)
        
        if [ "$perms" = "$expected_perms" ] && \
           [ "$owner" = "$expected_owner" ] && \
           [ "$group" = "$expected_group" ]; then
            log_pass "$file: $perms $owner:$group ✓"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "$file: $perms $owner:$group (expected: $expected_perms $expected_owner:$expected_group)"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        if [ -f "$file" ] || [ -d "$file" ]; then
            local current=$(stat -c "%a %U:%G" "$file")
            save_config "$rule_id" "$rule_name" "$current"
            
            chown "$expected_owner:$expected_group" "$file"
            chmod "$expected_perms" "$file"
            log_info "Fixed $file permissions to $expected_perms $expected_owner:$expected_group"
            ((FIXED_CHECKS++))
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        local original=$(get_original_config "$rule_id")
        if [ -n "$original" ] && [ -e "$file" ]; then
            local orig_perms=$(echo "$original" | awk '{print $1}')
            local orig_owner=$(echo "$original" | awk -F: '{print $1}' | awk '{print $2}')
            local orig_group=$(echo "$original" | awk -F: '{print $2}')
            
            chmod "$orig_perms" "$file" 2>/dev/null
            chown "$orig_owner:$orig_group" "$file" 2>/dev/null
            log_info "Restored $file permissions"
        fi
    fi
}

check_all_system_file_permissions() {
    log_info "=== System File Permissions ==="
    
    check_file_permissions "/etc/passwd" "644" "root" "root"
    check_file_permissions "/etc/passwd-" "644" "root" "root"
    check_file_permissions "/etc/group" "644" "root" "root"
    check_file_permissions "/etc/group-" "644" "root" "root"
    check_file_permissions "/etc/shadow" "640" "root" "shadow"
    check_file_permissions "/etc/shadow-" "640" "root" "shadow"
    check_file_permissions "/etc/gshadow" "640" "root" "shadow"
    check_file_permissions "/etc/gshadow-" "640" "root" "shadow"
    check_file_permissions "/etc/shells" "644" "root" "root"
    check_file_permissions "/etc/security/opasswd" "600" "root" "root"
}

# ============================================================================
# 9.2 World Writable Files
# ============================================================================

check_world_writable() {
    local rule_id="SYS-WORLD-WRITABLE"
    local rule_name="Ensure world writable files and directories are secured"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        log_info "Searching for world-writable files (this may take a while)..."
        local world_writable=$(find / -xdev -type f -perm -0002 ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null | head -20)
        
        if [ -z "$world_writable" ]; then
            log_pass "No world-writable files found"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "World-writable files found:"
            echo "$world_writable"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        save_config "$rule_id" "$rule_name" "world_writable_found"
        
        log_info "Removing world-writable permission from files..."
        find / -xdev -type f -perm -0002 ! -path "/proc/*" ! -path "/sys/*" -exec chmod o-w {} \; 2>/dev/null
        
        log_info "Fixed world-writable files"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        log_warn "World-writable rollback not recommended for security"
    fi
}

check_unowned_files() {
    local rule_id="SYS-UNOWNED-FILES"
    local rule_name="Ensure no files or directories without an owner and a group exist"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        log_info "Searching for unowned files..."
        local unowned=$(find / -xdev \( -nouser -o -nogroup \) ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null | head -20)
        
        if [ -z "$unowned" ]; then
            log_pass "No unowned files found"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "Unowned files found:"
            echo "$unowned"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        save_config "$rule_id" "$rule_name" "unowned_found"
        
        log_warn "Manual intervention required for unowned files"
        log_info "Use: chown <user>:<group> <file>"
        
    elif [ "$MODE" = "rollback" ]; then
        log_info "Manual review required"
    fi
}

check_suid_sgid_files() {
    local rule_id="SYS-SUID-SGID"
    local rule_name="Ensure SUID and SGID files are reviewed"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        log_info "Finding SUID/SGID files (this may take a while)..."
        local suid_files=$(find / -xdev -type f \( -perm -4000 -o -perm -2000 \) ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null)
        
        local count=$(echo "$suid_files" | wc -l)
        
        if [ -n "$suid_files" ]; then
            log_warn "Found $count SUID/SGID files - review recommended:"
            echo "$suid_files" | head -20
            if [ "$count" -gt 20 ]; then
                echo "... and $((count - 20)) more"
            fi
        fi
        
        log_pass "SUID/SGID files listed for review"
        ((PASSED_CHECKS++))
        return 0
        
    elif [ "$MODE" = "fix" ]; then
        log_warn "Manual review required for SUID/SGID files"
        log_info "Remove unnecessary SUID/SGID bits with: chmod u-s,g-s <file>"
        
    elif [ "$MODE" = "rollback" ]; then
        log_info "Manual review required"
    fi
}

# ============================================================================
# 9.3 User and Group Settings
# ============================================================================

check_passwd_shadowed() {
    local rule_id="SYS-PASSWD-SHADOWED"
    local rule_name="Ensure accounts in /etc/passwd use shadowed passwords"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        local unshadowed=$(awk -F: '($2 != "x" ) { print $1 }' /etc/passwd)
        
        if [ -z "$unshadowed" ]; then
            log_pass "All accounts use shadowed passwords"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "Unshadowed accounts found: $unshadowed"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        local unshadowed=$(awk -F: '($2 != "x" ) { print $1 }' /etc/passwd)
        
        if [ -n "$unshadowed" ]; then
            save_config "$rule_id" "$rule_name" "$unshadowed"
            
            for user in $unshadowed; do
                passwd -l "$user"
                log_info "Locked account: $user"
            done
            
            ((FIXED_CHECKS++))
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        log_warn "Account shadow rollback requires manual intervention"
    fi
}

check_empty_password_fields() {
    local rule_id="SYS-EMPTY-PASSWORDS"
    local rule_name="Ensure /etc/shadow password fields are not empty"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        local empty_pass=$(awk -F: '($2 == "" ) { print $1 }' /etc/shadow)
        
        if [ -z "$empty_pass" ]; then
            log_pass "No empty password fields"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "Accounts with empty passwords: $empty_pass"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        local empty_pass=$(awk -F: '($2 == "" ) { print $1 }' /etc/shadow)
        
        if [ -n "$empty_pass" ]; then
            save_config "$rule_id" "$rule_name" "$empty_pass"
            
            for user in $empty_pass; do
                passwd -l "$user"
                log_info "Locked account with empty password: $user"
            done
            
            ((FIXED_CHECKS++))
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        log_warn "Password field rollback requires manual intervention"
    fi
}

check_groups_exist() {
    local rule_id="SYS-GROUPS-EXIST"
    local rule_name="Ensure all groups in /etc/passwd exist in /etc/group"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        local missing_groups=""
        
        for gid in $(cut -d: -f4 /etc/passwd | sort -u); do
            if ! grep -q "^[^:]*:[^:]*:$gid:" /etc/group; then
                missing_groups="$missing_groups GID:$gid"
            fi
        done
        
        if [ -z "$missing_groups" ]; then
            log_pass "All groups exist"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "Missing groups:$missing_groups"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        save_config "$rule_id" "$rule_name" "missing_groups"
        log_warn "Manual intervention required to create missing groups"
        
    elif [ "$MODE" = "rollback" ]; then
        log_info "Manual review required"
    fi
}

check_duplicate_uids() {
    local rule_id="SYS-DUPLICATE-UIDS"
    local rule_name="Ensure no duplicate UIDs exist"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        local duplicates=$(cut -d: -f3 /etc/passwd | sort | uniq -d)
        
        if [ -z "$duplicates" ]; then
            log_pass "No duplicate UIDs"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "Duplicate UIDs found: $duplicates"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        local duplicates=$(cut -d: -f3 /etc/passwd | sort | uniq -d)
        
        if [ -n "$duplicates" ]; then
            save_config "$rule_id" "$rule_name" "$duplicates"
            log_warn "Manual intervention required to resolve duplicate UIDs"
        fi
    fi
}

check_duplicate_gids() {
    local rule_id="SYS-DUPLICATE-GIDS"
    local rule_name="Ensure no duplicate GIDs exist"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        local duplicates=$(cut -d: -f3 /etc/group | sort | uniq -d)
        
        if [ -z "$duplicates" ]; then
            log_pass "No duplicate GIDs"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "Duplicate GIDs found: $duplicates"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        local duplicates=$(cut -d: -f3 /etc/group | sort | uniq -d)
        
        if [ -n "$duplicates" ]; then
            save_config "$rule_id" "$rule_name" "$duplicates"
            log_warn "Manual intervention required to resolve duplicate GIDs"
        fi
    fi
}

check_duplicate_usernames() {
    local rule_id="SYS-DUPLICATE-USERNAMES"
    local rule_name="Ensure no duplicate user names exist"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        local duplicates=$(cut -d: -f1 /etc/passwd | sort | uniq -d)
        
        if [ -z "$duplicates" ]; then
            log_pass "No duplicate usernames"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "Duplicate usernames found: $duplicates"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        local duplicates=$(cut -d: -f1 /etc/passwd | sort | uniq -d)
        
        if [ -n "$duplicates" ]; then
            save_config "$rule_id" "$rule_name" "$duplicates"
            log_warn "Manual intervention required to resolve duplicate usernames"
        fi
    fi
}

check_duplicate_groupnames() {
    local rule_id="SYS-DUPLICATE-GROUPNAMES"
    local rule_name="Ensure no duplicate group names exist"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        local duplicates=$(cut -d: -f1 /etc/group | sort | uniq -d)
        
        if [ -z "$duplicates" ]; then
            log_pass "No duplicate group names"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "Duplicate group names found: $duplicates"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        local duplicates=$(cut -d: -f1 /etc/group | sort | uniq -d)
        
        if [ -n "$duplicates" ]; then
            save_config "$rule_id" "$rule_name" "$duplicates"
            log_warn "Manual intervention required to resolve duplicate group names"
        fi
    fi
}

check_shadow_group_empty() {
    local rule_id="SYS-SHADOW-GROUP"
    local rule_name="Ensure shadow group is empty"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        local shadow_members=$(grep "^shadow:" /etc/group | cut -d: -f4)
        
        if [ -z "$shadow_members" ]; then
            log_pass "Shadow group is empty"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "Shadow group has members: $shadow_members"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        local shadow_members=$(grep "^shadow:" /etc/group | cut -d: -f4)
        
        if [ -n "$shadow_members" ]; then
            save_config "$rule_id" "$rule_name" "$shadow_members"
            
            # Remove all members from shadow group
            gpasswd -M "" shadow 2>/dev/null
            
            log_info "Removed members from shadow group"
            ((FIXED_CHECKS++))
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        local original=$(get_original_config "$rule_id")
        if [ -n "$original" ]; then
            log_warn "Manual restoration of shadow group members required"
            log_info "Original members: $original"
        fi
    fi
}

check_user_home_directories() {
    local rule_id="SYS-HOME-DIRS"
    local rule_name="Ensure local interactive user home directories are configured"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        local issues=0
        
        while IFS=: read -r user _ uid _ _ home _; do
            if [ "$uid" -ge 1000 ] && [ "$user" != "nobody" ]; then
                if [ ! -d "$home" ]; then
                    log_warn "Home directory missing for $user: $home"
                    ((issues++))
                fi
            fi
        done < /etc/passwd
        
        if [ $issues -eq 0 ]; then
            log_pass "All user home directories exist"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "Found $issues home directory issues"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        save_config "$rule_id" "$rule_name" "home_dir_issues"
        
        while IFS=: read -r user _ uid _ _ home _; do
            if [ "$uid" -ge 1000 ] && [ "$user" != "nobody" ]; then
                if [ ! -d "$home" ]; then
                    mkdir -p "$home"
                    chown "$user:$user" "$home"
                    chmod 750 "$home"
                    log_info "Created home directory for $user"
                fi
            fi
        done < /etc/passwd
        
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        log_warn "Home directory rollback not recommended"
    fi
}

# ============================================================================
# Main Execution
# ============================================================================

main() {
    echo "========================================================================"
    echo "System Maintenance Hardening Script"
    echo "Mode: $MODE"
    echo "========================================================================"
    
    if [ "$MODE" = "scan" ] || [ "$MODE" = "fix" ]; then
        check_all_system_file_permissions
        
        log_info ""
        log_info "=== World Writable and Unowned Files ==="
        check_world_writable
        check_unowned_files
        check_suid_sgid_files
        
        log_info ""
        log_info "=== User and Group Settings ==="
        check_passwd_shadowed
        check_empty_password_fields
        check_groups_exist
        check_duplicate_uids
        check_duplicate_gids
        check_duplicate_usernames
        check_duplicate_groupnames
        check_shadow_group_empty
        check_user_home_directories
        
        echo ""
        echo "========================================================================"
        echo "Summary"
        echo "========================================================================"
        echo "Total Checks: $TOTAL_CHECKS"
        
        if [ "$MODE" = "scan" ]; then
            echo "Passed: $PASSED_CHECKS"
            echo "Failed: $FAILED_CHECKS"
            
            if [ $FAILED_CHECKS -eq 0 ]; then
                log_pass "All system maintenance checks passed!"
            else
                log_warn "$FAILED_CHECKS checks failed. Run with 'fix' mode to remediate."
            fi
        else
            echo "Fixed: $FIXED_CHECKS"
            log_info "Fixes applied. Run 'scan' mode to verify."
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        log_info "Rolling back system maintenance configurations..."
        check_all_system_file_permissions
        check_shadow_group_empty
        log_info "Rollback completed"
    else
        echo "Usage: $0 {scan|fix|rollback}"
        exit 1
    fi
}

main
