#!/bin/bash
# Filesystem Hardening Script
# Supports: scan, fix, rollback modes
# SAFE VERSION - Warns about partition separation, only fixes mount options

MODE="${1:-scan}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_PATH="$SCRIPT_DIR/../hardening.db"
BACKUP_DIR="$SCRIPT_DIR/../backups/filesystem"
TOPIC="Filesystem"

mkdir -p "$BACKUP_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
FIXED_CHECKS=0
MANUAL_CHECKS=0

# Track if fstab was modified (to run mount -a once at the end)
FSTAB_MODIFIED=false

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[FAIL]${NC} $1"
}

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

log_manual() {
    echo -e "${BLUE}[MANUAL]${NC} $1"
}

# Save configuration to database via Python helper
save_config() {
    local rule_id="$1"
    local rule_name="$2"
    local original_value="$3"
    local current_value="${4:-$original_value}"
    
    # Run the Python command
    python3 -c "
import sqlite3
import sys
try:
    conn = sqlite3.connect('$DB_PATH')
    cursor = conn.cursor()
    # Ensure the table is created if it somehow doesn't exist yet
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS configurations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            topic TEXT NOT NULL,
            rule_id TEXT NOT NULL UNIQUE,
            rule_name TEXT NOT NULL,
            original_value TEXT,
            current_value TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'original'
        );
    ''')
    cursor.execute('''
        INSERT OR REPLACE INTO configurations 
        (topic, rule_id, rule_name, original_value, current_value, status)
        VALUES (?, ?, ?, ?, ?, 'stored')
    ''', ('$TOPIC', '$rule_id', '''$rule_name''', '''$original_value''', '''$current_value'''))
    conn.commit()
    conn.close()
except sqlite3.Error as e:
    # Print the specific error to stderr
    print(f'Database error in shell script: {e}', file=sys.stderr)
    sys.exit(1)
"
    
    # Check the exit status of the python command explicitly
    if [ $? -ne 0 ]; then
        log_warn "Could not save configuration to database for $rule_id. Check stderr output for details."
    fi
}

get_original_config() {
    local rule_id="$1"
    python3 -c "
import sqlite3
import sys
try:
    conn = sqlite3.connect('$DB_PATH')
    cursor = conn.cursor()
    cursor.execute('SELECT original_value FROM configurations WHERE topic=? AND rule_id=?', ('$TOPIC', '$rule_id'))
    result = cursor.fetchone()
    conn.close()
    print(result[0] if result else '')
except Exception as e:
    print('', file=sys.stderr)
" 2>/dev/null
}

# ============================================================================
# Helper Functions
# ============================================================================

# Check if a directory is on the root filesystem
is_on_root_filesystem() {
    local dir="$1"
    
    # Handle non-existent directories
    if [ ! -d "$dir" ]; then
        return 2  # Directory doesn't exist
    fi
    
    local dir_device
    local root_device
    dir_device=$(df "$dir" 2>/dev/null | tail -1 | awk '{print $1}')
    root_device=$(df / 2>/dev/null | tail -1 | awk '{print $1}')
    
    if [ -z "$dir_device" ] || [ -z "$root_device" ]; then
        return 2  # Could not determine
    fi
    
    if [ "$dir_device" = "$root_device" ]; then
        return 0  # True - on root filesystem
    else
        return 1  # False - separate partition
    fi
}

# Check if directory exists in fstab
fstab_has_entry() {
    local partition="$1"
    grep -q "^[^#]*[[:space:]]$partition[[:space:]]" /etc/fstab 2>/dev/null
}

# Get current mount options for a partition
get_mount_options() {
    local partition="$1"
    mount | grep " on $partition " | sed 's/.*(\(.*\))/\1/' 2>/dev/null
}

# Check if mount has specific option
has_mount_option() {
    local options_list="$1"
    local option="$2"
    echo "$options_list" | grep -qw "$option"
}

# Check if partition is mounted
is_mounted() {
    local partition="$1"
    mount | grep -q " on $partition " 2>/dev/null
}

# Validate fstab syntax
validate_fstab() {
    findmnt --verify --verbose 2>&1 | grep -i "error" && return 1
    return 0
}

# ============================================================================
# 1.1 Filesystem Kernel Modules
# ============================================================================

check_kernel_module() {
    local module="$1"
    local rule_id="FS-KM-$(echo "$module" | tr '[:lower:]' '[:upper:]' | tr '-' '_')"
    local rule_name="Ensure $module kernel module is not available"
    
    ((TOTAL_CHECKS++))
    
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        # Check if module is loaded
        if lsmod | grep -q "^$module "; then
            log_error "Module $module is currently loaded"
            ((FAILED_CHECKS++))
            return 1
        fi
        
        # Check if install directive exists with /bin/false or /bin/true
        if grep -rq "^[[:space:]]*install[[:space:]]\+$module[[:space:]]\+/bin/\(false\|true\)" /etc/modprobe.d/ 2>/dev/null; then
            log_pass "Module $module is properly disabled"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "Module $module is not properly disabled"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        # Save current state
        local current_state="not_disabled"
        if grep -rq "^[[:space:]]*install[[:space:]]\+$module[[:space:]]\+/bin/\(false\|true\)" /etc/modprobe.d/ 2>/dev/null; then
            current_state="disabled"
        fi
        save_config "$rule_id" "$rule_name" "$current_state"
        
        # Create blacklist file with install directive
        local modprobe_file="/etc/modprobe.d/$module-blacklist.conf"
        
        cat > "$modprobe_file" << EOF
# Disable $module module - Added by hardening script
install $module /bin/false
blacklist $module
EOF
        
        if [ $? -eq 0 ]; then
            log_info "Created blacklist configuration: $modprobe_file"
            
            # Unload module if loaded
            if lsmod | grep -q "^$module "; then
                if rmmod "$module" 2>/dev/null || modprobe -r "$module" 2>/dev/null; then
                    log_info "Module $module unloaded successfully"
                else
                    log_warn "Could not unload module $module (may be in use or require reboot)"
                fi
            fi
            
            log_pass "Module $module has been disabled"
            ((FIXED_CHECKS++))
        else
            log_error "Failed to create blacklist file for $module"
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        local original
        original=$(get_original_config "$rule_id")
        if [ "$original" = "not_disabled" ]; then
            local modprobe_file="/etc/modprobe.d/$module-blacklist.conf"
            if [ -f "$modprobe_file" ]; then
                rm -f "$modprobe_file"
                log_info "Removed blacklist for $module"
            fi
        fi
    fi
}

check_all_kernel_modules() {
    log_info "=== Checking Filesystem Kernel Modules ==="
    
    # Keep kernel module logic intact as requested
    check_kernel_module "cramfs"
    check_kernel_module "freevxfs"
    check_kernel_module "hfs"
    check_kernel_module "hfsplus"
    check_kernel_module "jffs2"
    check_kernel_module "overlayfs"
    check_kernel_module "squashfs"
    check_kernel_module "udf"
    check_kernel_module "usb-storage"
}

# ============================================================================
# 1.2 Filesystem Partitions - SAFE VERSION
# ============================================================================

check_partition_exists() {
    local partition="$1"
    local rule_id="FS-PART-$(echo "$partition" | tr '/' '-' | tr '[:lower:]' '[:upper:]')-EXISTS"
    local rule_name="Check if $partition is a separate partition"
    
    ((TOTAL_CHECKS++))
    
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ ! -d "$partition" ]; then
        log_warn "Directory $partition does not exist"
        ((MANUAL_CHECKS++))
        return 2
    fi
    
    if [ "$MODE" = "scan" ] || [ "$MODE" = "fix" ]; then
        if is_mounted "$partition"; then
            if is_on_root_filesystem "$partition"; then
                log_warn "$partition exists but is on root filesystem (not a separate partition)"
                ((FAILED_CHECKS++))
                return 1
            else
                log_pass "$partition is a separate partition"
                ((PASSED_CHECKS++))
                return 0
            fi
        else
            log_error "$partition is not mounted"
            ((FAILED_CHECKS++))
            return 1
        fi
    fi
}

check_partition_option() {
    local partition="$1"
    local option="$2"
    local rule_id="FS-PART-$(echo "$partition" | tr '/' '-' | tr '[:lower:]' '[:upper:]')-OPT-$(echo "$option" | tr '[:lower:]' '[:upper:]')"
    local rule_name="Ensure $option is set on $partition"
    
    ((TOTAL_CHECKS++))
    
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ ! -d "$partition" ] && [ "$partition" != "/dev/shm" ]; then
        log_warn "Directory $partition does not exist"
        ((MANUAL_CHECKS++))
        return 2
    fi
    
    if [ "$MODE" = "scan" ]; then
        if ! is_mounted "$partition"; then
            log_error "$partition is not mounted"
            ((FAILED_CHECKS++))
            return 1
        fi
        
        local current_options
        current_options=$(get_mount_options "$partition")
        
        if has_mount_option "$current_options" "$option"; then
            log_pass "$partition has $option option set"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "$partition does not have $option option set"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        if ! is_mounted "$partition"; then
            log_error "Cannot fix: $partition is not mounted"
            return 1
        fi
        
        if ! fstab_has_entry "$partition"; then
            log_error "Cannot fix: No fstab entry found for $partition"
            log_manual "Add $partition to /etc/fstab first, then re-run this script"
            ((MANUAL_CHECKS++))
            return 1
        fi
        
        local current_options
        current_options=$(get_mount_options "$partition")
        
        if has_mount_option "$current_options" "$option"; then
            log_pass "$partition already has $option option set"
            return 0
        fi
        
        # Backup fstab
        cp /etc/fstab "$BACKUP_DIR/fstab.$(date +%Y%m%d_%H%M%S)"
        
        # Get current fstab line
        local original_line
        original_line=$(grep "^[^#]*[[:space:]]$partition[[:space:]]" /etc/fstab)
        save_config "$rule_id" "$rule_name" "$original_line"
        
        # Add option to fstab
        local temp_file
        temp_file=$(mktemp)
        awk -v partition="$partition" -v opt="$option" '
        $2 == partition {
            if ($4 == "defaults") {
                $4 = "defaults," opt
            } else if ($4 !~ opt) {
                $4 = $4 "," opt
            }
        }
        { print }
        ' /etc/fstab > "$temp_file" && mv "$temp_file" /etc/fstab
        
        if [ $? -eq 0 ]; then
            log_info "Added $option to $partition in fstab"
            FSTAB_MODIFIED=true
            ((FIXED_CHECKS++))
        else
            log_error "Failed to update fstab for $partition"
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        local original_line
        original_line=$(get_original_config "$rule_id")
        
        if [ -n "$original_line" ]; then
            # Remove current line and add original back
            sed -i "\|[[:space:]]$partition[[:space:]]|d" /etc/fstab
            echo "$original_line" >> /etc/fstab
            log_info "Rolled back fstab configuration for $partition"
            FSTAB_MODIFIED=true
        else
            log_warn "No original config found for $rule_id to rollback"
        fi
    fi
}

check_partition_complete() {
    local partition="$1"
    shift
    local options=("$@")
    
    log_info "=== Checking $partition Configuration ==="
    
    # First check if partition exists/is separate
    check_partition_exists "$partition"
    local exists_status=$?
    
    # If partition doesn't exist or isn't mounted, show manual instructions
    if [ $exists_status -eq 1 ] || [ $exists_status -eq 2 ]; then
        if [ "$MODE" = "fix" ]; then
            log_manual "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            log_manual "RECOMMENDED: Create separate partition for $partition"
            log_manual "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            log_manual "Security best practice: Each critical directory should"
            log_manual "be on its own partition to prevent DoS attacks and"
            log_manual "limit the impact of disk space exhaustion."
            log_manual ""
            log_manual "Required mount options for $partition: ${options[*]}"
            log_manual "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            ((MANUAL_CHECKS++))
        fi
    fi
    
    # Check each mount option
    for opt in "${options[@]}"; do
        check_partition_option "$partition" "$opt"
    done
}

# ============================================================================
# Partition Checks
# ============================================================================

check_tmp_partition() {
    check_partition_complete "/tmp" "nodev" "nosuid" "noexec"
}

check_dev_shm_partition() {
    check_partition_complete "/dev/shm" "nodev" "nosuid" "noexec"
}

check_home_partition() {
    check_partition_complete "/home" "nodev" "nosuid"
}

check_var_partition() {
    check_partition_complete "/var" "nodev" "nosuid"
}

check_var_tmp_partition() {
    check_partition_complete "/var/tmp" "nodev" "nosuid" "noexec"
}

check_var_log_partition() {
    check_partition_complete "/var/log" "nodev" "nosuid" "noexec"
}

check_var_log_audit_partition() {
    check_partition_complete "/var/log/audit" "nodev" "nosuid" "noexec"
}

# ============================================================================
# Main Execution
# ============================================================================

main() {
    echo "========================================================================"
    echo "Filesystem Hardening Script - SAFE VERSION"
    echo "Mode: $MODE"
    echo "========================================================================"
    
    # Check if running as root for fix/rollback modes
    if [ "$MODE" = "fix" ] || [ "$MODE" = "rollback" ]; then
        if [ "$EUID" -ne 0 ]; then
            log_error "This script must be run as root for $MODE mode"
            exit 1
        fi
    fi
    
    if [ "$MODE" = "scan" ] || [ "$MODE" = "fix" ]; then
        # Kernel modules (unchanged as requested)
        check_all_kernel_modules
        
        # Partition checks (safe version - warnings only)
        check_tmp_partition
        check_dev_shm_partition
        check_home_partition
        check_var_partition
        check_var_tmp_partition
        check_var_log_partition
        check_var_log_audit_partition
        
        # Apply fstab changes if any were made
        if [ "$MODE" = "fix" ] && [ "$FSTAB_MODIFIED" = "true" ]; then
            echo ""
            log_info "========================================================================"
            log_info "Applying fstab changes..."
            log_info "========================================================================"
            
            # Test mount first
            if mount -a --test 2>/dev/null; then
                log_info "fstab syntax is valid"
                
                # Remount partitions with new options
                for part in /var/log/audit /var/log /var/tmp /var /home /tmp /dev/shm; do
                    if is_mounted "$part" && fstab_has_entry "$part"; then
                        if mount -o remount "$part" 2>/dev/null; then
                            log_pass "Remounted $part with new options"
                        else
                            log_warn "Could not remount $part - may require manual intervention"
                        fi
                    fi
                done
            else
                log_error "fstab syntax validation failed - changes not applied"
                log_error "Please check /etc/fstab manually"
                log_info "Backup available at: $BACKUP_DIR"
            fi
        fi
        
        echo ""
        echo "========================================================================"
        echo "Summary"
        echo "========================================================================"
        echo "Total Checks: $TOTAL_CHECKS"
        
        if [ "$MODE" = "scan" ]; then
            echo "Passed: $PASSED_CHECKS"
            echo "Failed: $FAILED_CHECKS"
            
            if [ $FAILED_CHECKS -eq 0 ]; then
                log_pass "All filesystem checks passed!"
            else
                log_warn "$FAILED_CHECKS checks failed. Run with 'fix' mode to remediate."
            fi
        else
            echo "Fixed: $FIXED_CHECKS"
            echo "Manual Actions Required: $MANUAL_CHECKS"
            
            if [ $MANUAL_CHECKS -gt 0 ]; then
                echo ""
                log_manual "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                log_manual "IMPORTANT: $MANUAL_CHECKS items require manual action"
                log_manual "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                log_manual "Scroll up to review manual action items marked with [MANUAL]"
                log_manual "These items cannot be automatically fixed for safety reasons."
                log_manual "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            fi
            
            if [ "$FSTAB_MODIFIED" = "true" ]; then
                log_info "fstab has been modified. Changes have been applied."
                log_info "Backup available at: $BACKUP_DIR"
                log_info "Run 'scan' mode to verify all changes."
            else
                log_info "No fstab changes were necessary."
            fi
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        if [ "$EUID" -ne 0 ]; then
            log_error "This script must be run as root for rollback mode"
            exit 1
        fi
        
        log_info "Rolling back filesystem configurations..."
        
        # Rollback kernel modules
        for module in cramfs freevxfs hfs hfsplus jffs2 overlayfs squashfs udf usb-storage; do
            check_kernel_module "$module"
        done
        
        # Restore latest fstab backup
        local latest_backup
        latest_backup=$(ls -t "$BACKUP_DIR"/fstab.* 2>/dev/null | head -1)
        if [ -n "$latest_backup" ]; then
            if cp "$latest_backup" /etc/fstab; then
                log_info "Restored fstab from backup: $latest_backup"
                
                # Remount all partitions
                mount -a 2>/dev/null
                log_info "Reapplied fstab mounts"
            else
                log_error "Failed to restore fstab backup"
            fi
        else
            log_warn "No fstab backup found to restore"
        fi
        
        log_info "Rollback completed"
    else
        echo "Usage: $0 {scan|fix|rollback}"
        echo ""
        echo "Modes:"
        echo "  scan     - Check current filesystem configuration (read-only)"
        echo "  fix      - Fix mount options for existing partitions (requires root)"
        echo "             WARNING: Does NOT create partitions automatically"
        echo "  rollback - Restore previous configuration (requires root)"
        exit 1
    fi
}

main
