#!/bin/bash
# Filesystem Hardening Script
# Supports: scan, fix, rollback modes

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
NC='\033[0m' # No Color

# Counters
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
FIXED_CHECKS=0

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

# Save configuration to database via Python helper
save_config() {
    local rule_id="$1"
    local rule_name="$2"
    local original_value="$3"
    local current_value="${4:-$original_value}"
    
    python3 -c "
import sqlite3
conn = sqlite3.connect('$DB_PATH')
cursor = conn.cursor()
cursor.execute('''
    INSERT OR REPLACE INTO configurations 
    (topic, rule_id, rule_name, original_value, current_value, status)
    VALUES (?, ?, ?, ?, ?, 'stored')
''', ('$TOPIC', '$rule_id', '''$rule_name''', '''$original_value''', '''$current_value'''))
conn.commit()
conn.close()
"
}

get_original_config() {
    local rule_id="$1"
    python3 -c "
import sqlite3
conn = sqlite3.connect('$DB_PATH')
cursor = conn.cursor()
cursor.execute('SELECT original_value FROM configurations WHERE topic=? AND rule_id=?', ('$TOPIC', '$rule_id'))
result = cursor.fetchone()
conn.close()
print(result[0] if result else '')
"
}

# ============================================================================
# 1.1 Filesystem Kernel Modules
# ============================================================================

check_kernel_module() {
    local module="$1"
    local rule_id="FS-KM-$(echo $module | tr '[:lower:]' '[:upper:]')"
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
        if grep -rq "^[[:space:]]*install[[:space:]]\+$module[[:space:]]\+/bin/false" /etc/modprobe.d/ || \
           grep -rq "^[[:space:]]*install[[:space:]]\+$module[[:space:]]\+/bin/true" /etc/modprobe.d/; then
            log_pass "Module $module is properly disabled (install directive found)"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "Module $module is not properly disabled (no install directive found)"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        # Save current state
        local current_state="not_disabled"
        if grep -rq "^[[:space:]]*install[[:space:]]\+$module[[:space:]]\+/bin/false" /etc/modprobe.d/ || \
           grep -rq "^[[:space:]]*install[[:space:]]\+$module[[:space:]]\+/bin/true" /etc/modprobe.d/; then
            current_state="disabled"
        fi
        save_config "$rule_id" "$rule_name" "$current_state"
        
        # Create blacklist file with install directive
        cat > "/etc/modprobe.d/$module-blacklist.conf" << EOF
# Disable $module module
install $module /bin/false
blacklist $module
EOF
        
        # Unload module if loaded
        if lsmod | grep -q "^$module "; then
            rmmod "$module" 2>/dev/null || modprobe -r "$module" 2>/dev/null
            if [ $? -eq 0 ]; then
                log_info "Module $module has been unloaded"
            else
                log_warn "Could not unload module $module (may require reboot)"
            fi
        fi
        
        log_info "Module $module has been disabled with install directive"
        ((FIXED_CHECKS++))
        
    elif [ "$MODE" = "rollback" ]; then
        local original=$(get_original_config "$rule_id")
        if [ "$original" = "not_disabled" ]; then
            rm -f "/etc/modprobe.d/$module-blacklist.conf"
            log_info "Removed blacklist for $module"
        fi
    fi
}

check_all_kernel_modules() {
    log_info "=== Checking Filesystem Kernel Modules ==="
    
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
# 1.2 Filesystem Partitions
# ============================================================================

check_partition() {
    local partition="$1"
    local option="$2"
    local rule_id="FS-PART-$(echo $partition | tr '/' '-' | tr '[:lower:]' '[:upper:]')-$(echo $option | tr '[:lower:]' '[:upper:]')"
    local rule_name="Ensure $option option set on $partition partition"
    
    ((TOTAL_CHECKS++))
    
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        # Check if partition exists
        if ! mount | grep -q " on $partition "; then
            log_warn "Partition $partition does not exist or is not mounted"
            ((FAILED_CHECKS++))
            return 1
        fi
        
        # Check for specific option in mount output
        if mount | grep " on $partition " | grep -q "$option"; then
            log_pass "Partition $partition has $option option"
            ((PASSED_CHECKS++))
            return 0
        else
            log_error "Partition $partition missing $option option"
            ((FAILED_CHECKS++))
            return 1
        fi
        
    elif [ "$MODE" = "fix" ]; then
        # Check if partition exists first
        if ! mount | grep -q " on $partition "; then
            log_warn "Partition $partition does not exist - cannot apply $option option"
            return 1
        fi
        
        # Save current state
        local current_opts=$(mount | grep " on $partition " | sed 's/.*(\(.*\))/\1/')
        save_config "$rule_id" "$rule_name" "$current_opts"
        
        # Backup fstab
        cp /etc/fstab "$BACKUP_DIR/fstab.$(date +%Y%m%d_%H%M%S)"
        
        # Check if partition entry exists in fstab
        if grep -q " $partition " /etc/fstab; then
            # Check if option already present in fstab
            if grep " $partition " /etc/fstab | grep -q "$option"; then
                log_info "$partition already has $option in fstab"
            else
                # Add option - handle different fstab formats
                if grep " $partition " /etc/fstab | grep -q "defaults"; then
                    # Add to defaults
                    sed -i "/ $partition /s/defaults/defaults,$option/" /etc/fstab
                else
                    # Get current options and append
                    local fstab_opts=$(grep " $partition " /etc/fstab | awk '{print $4}')
                    sed -i "/ $partition /s/$fstab_opts/$fstab_opts,$option/" /etc/fstab
                fi
                log_info "Added $option to $partition in /etc/fstab"
            fi
            
            # Remount partition with new options
            if mount -o remount,"$option" "$partition" 2>/dev/null; then
                log_info "Successfully remounted $partition with $option option"
                ((FIXED_CHECKS++))
            else
                log_warn "Failed to remount $partition - may require reboot"
                ((FIXED_CHECKS++))
            fi
        else
            log_warn "Partition $partition not found in /etc/fstab - manual configuration required"
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        local original=$(get_original_config "$rule_id")
        if [ -n "$original" ]; then
            # Find most recent backup
            local latest_backup=$(ls -t "$BACKUP_DIR"/fstab.* 2>/dev/null | head -1)
            if [ -n "$latest_backup" ]; then
                cp "$latest_backup" /etc/fstab
                mount -o remount "$partition" 2>/dev/null
                log_info "Restored original fstab for $partition"
            fi
        fi
    fi
}

check_tmp_partition() {
    log_info "=== Checking /tmp Partition ==="
    
    local rule_id="FS-TMP-SEPARATE"
    local rule_name="Ensure /tmp is a separate partition"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if mount | grep -q " on /tmp "; then
            log_pass "/tmp is a separate partition"
            ((PASSED_CHECKS++))
        else
            log_error "/tmp is not a separate partition"
            ((FAILED_CHECKS++))
        fi
    elif [ "$MODE" = "fix" ]; then
        if ! mount | grep -q " on /tmp "; then
            log_warn "/tmp partition creation requires manual intervention"
            log_info "Consider using systemd tmp.mount or creating a dedicated partition"
        fi
    fi
    
    # Check options if partition exists
    if mount | grep -q " on /tmp "; then
        check_partition "/tmp" "nodev"
        check_partition "/tmp" "nosuid"
        check_partition "/tmp" "noexec"
    fi
}

check_dev_shm_partition() {
    log_info "=== Checking /dev/shm Partition ==="
    
    local rule_id="FS-DEVSHM-SEPARATE"
    local rule_name="Ensure /dev/shm exists"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if mount | grep -q " on /dev/shm "; then
            log_pass "/dev/shm is mounted"
            ((PASSED_CHECKS++))
        else
            log_error "/dev/shm is not mounted"
            ((FAILED_CHECKS++))
        fi
    elif [ "$MODE" = "fix" ]; then
        if ! mount | grep -q " on /dev/shm "; then
            log_warn "/dev/shm is not mounted - this is unusual"
        fi
    fi
    
    # Check options if partition exists
    if mount | grep -q " on /dev/shm "; then
        check_partition "/dev/shm" "nodev"
        check_partition "/dev/shm" "nosuid"
        check_partition "/dev/shm" "noexec"
    fi
}

check_home_partition() {
    log_info "=== Checking /home Partition ==="
    
    local rule_id="FS-HOME-SEPARATE"
    local rule_name="Ensure separate partition exists for /home"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if mount | grep -q " on /home "; then
            log_pass "/home is a separate partition"
            ((PASSED_CHECKS++))
        else
            log_warn "/home is not a separate partition (recommended)"
            ((FAILED_CHECKS++))
        fi
    elif [ "$MODE" = "fix" ]; then
        if ! mount | grep -q " on /home "; then
            log_warn "/home partition creation requires manual intervention"
        fi
    fi
    
    # Check options if partition exists
    if mount | grep -q " on /home "; then
        check_partition "/home" "nodev"
        check_partition "/home" "nosuid"
    fi
}

check_var_partitions() {
    log_info "=== Checking /var Partitions ==="
    
    for part in "/var" "/var/tmp" "/var/log" "/var/log/audit"; do
        local part_clean=$(echo $part | tr '/' '-')
        local rule_id="FS-VAR${part_clean}-SEPARATE"
        local rule_name="Ensure separate partition exists for $part"
        
        ((TOTAL_CHECKS++))
        echo ""
        echo "Checking: $rule_name"
        echo "Rule ID: $rule_id"
        
        if [ "$MODE" = "scan" ]; then
            if mount | grep -q " on $part "; then
                log_pass "$part is a separate partition"
                ((PASSED_CHECKS++))
            else
                log_warn "$part is not a separate partition (recommended)"
                ((FAILED_CHECKS++))
            fi
        elif [ "$MODE" = "fix" ]; then
            if ! mount | grep -q " on $part "; then
                log_warn "$part partition creation requires manual intervention"
            fi
        fi
        
        # Check options if partition exists
        if mount | grep -q " on $part "; then
            check_partition "$part" "nodev"
            check_partition "$part" "nosuid"
            if [ "$part" != "/var" ]; then
                check_partition "$part" "noexec"
            fi
        fi
    done
}

# ============================================================================
# Main Execution
# ============================================================================

main() {
    echo "========================================================================"
    echo "Filesystem Hardening Script"
    echo "Mode: $MODE"
    echo "========================================================================"
    
    if [ "$MODE" = "scan" ] || [ "$MODE" = "fix" ]; then
        check_all_kernel_modules
        check_tmp_partition
        check_dev_shm_partition
        check_home_partition
        check_var_partitions
        
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
            log_info "Fixes applied. Run 'scan' mode to verify."
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        log_info "Rolling back filesystem configurations..."
        
        # Rollback kernel modules
        for module in cramfs freevxfs hfs hfsplus jffs2 overlayfs squashfs udf usb-storage; do
            check_kernel_module "$module"
        done
        
        log_info "Rollback completed"
    else
        echo "Usage: $0 {scan|fix|rollback}"
        exit 1
    fi
}

main
