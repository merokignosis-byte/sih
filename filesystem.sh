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
# Helper Functions
# ============================================================================

# Check if a directory is on the root filesystem
is_on_root_filesystem() {
    local dir="$1"
    local dir_device=$(df "$dir" 2>/dev/null | tail -1 | awk '{print $1}')
    local root_device=$(df / | tail -1 | awk '{print $1}')
    
    if [ "$dir_device" = "$root_device" ]; then
        return 0  # True - on root filesystem
    else
        return 1  # False - separate partition
    fi
}

# Check if directory exists in fstab
fstab_has_entry() {
    local partition="$1"
    grep -q "^[^#]*[[:space:]]$partition[[:space:]]" /etc/fstab
}

# Get current mount options for a partition
get_mount_options() {
    local partition="$1"
    mount | grep " on $partition " | sed 's/.*(\(.*\))/\1/'
}

# Check if mount has specific option
has_mount_option() {
    local partition="$1"
    local option="$2"
    mount | grep " on $partition " | grep -q "$option"
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
        # Check if partition/directory is mounted
        if ! mount | grep -q " on $partition "; then
            log_warn "Partition $partition does not exist or is not mounted"
            ((FAILED_CHECKS++))
            return 1
        fi
        
        # Check for specific option in mount output
        if has_mount_option "$partition" "$option"; then
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
        if [ ! -d "$partition" ]; then
            log_warn "Directory $partition does not exist - cannot apply $option option"
            return 1
        fi
        
        # Save current state
        local current_opts=$(get_mount_options "$partition")
        save_config "$rule_id" "$rule_name" "$current_opts"
        
        # Backup fstab before any modification
        if [ "$FSTAB_MODIFIED" = "false" ]; then
            cp /etc/fstab "$BACKUP_DIR/fstab.$(date +%Y%m%d_%H%M%S)"
            log_info "Created fstab backup"
        fi
        
        # Determine if this is a tmpfs mount (special handling)
        local is_tmpfs=false
        if [ "$partition" = "/tmp" ] || [ "$partition" = "/dev/shm" ]; then
            is_tmpfs=true
        fi
        
        # Check if partition already has an entry in fstab
        if fstab_has_entry "$partition"; then
            # Entry exists - modify it to add missing option
            if grep "^[^#]*[[:space:]]$partition[[:space:]]" /etc/fstab | grep -q "$option"; then
                log_info "$partition already has $option in fstab"
            else
                # Add the option to existing entry
                sed -i "/^[^#]*[[:space:]]$partition[[:space:]]/s/\([[:space:]][^[:space:]]*[[:space:]][^[:space:]]*[[:space:]]\)\([^[:space:]]*\)/\1\2,$option/" /etc/fstab
                log_info "Added $option to existing $partition entry in fstab"
                FSTAB_MODIFIED=true
                ((FIXED_CHECKS++))
            fi
        else
            # No entry exists - need to add one
            if is_on_root_filesystem "$partition" && [ "$is_tmpfs" = "false" ]; then
                # Directory is on root filesystem - create bind mount
                log_info "$partition is on root filesystem - creating bind mount entry"
                
                # Determine appropriate options
                local mount_opts="defaults,bind,$option"
                
                # Add bind mount entry to fstab
                echo "" >> /etc/fstab
                echo "# Bind mount for $partition with security options" >> /etc/fstab
                echo "$partition    $partition    none    $mount_opts    0 0" >> /etc/fstab
                
                log_info "Added bind mount entry for $partition with $option option"
                FSTAB_MODIFIED=true
                ((FIXED_CHECKS++))
                
            elif [ "$is_tmpfs" = "true" ]; then
                # This is a tmpfs mount - add tmpfs entry
                log_info "$partition should be tmpfs - creating tmpfs entry"
                
                local mount_opts="defaults,$option"
                local size_opt=""
                
                if [ "$partition" = "/tmp" ]; then
                    size_opt=",size=2G"  # Adjust size as needed
                elif [ "$partition" = "/dev/shm" ]; then
                    size_opt=",size=1G"  # Adjust size as needed
                fi
                
                echo "" >> /etc/fstab
                echo "# Tmpfs mount for $partition with security options" >> /etc/fstab
                echo "tmpfs    $partition    tmpfs    ${mount_opts}${size_opt}    0 0" >> /etc/fstab
                
                log_info "Added tmpfs entry for $partition with $option option"
                FSTAB_MODIFIED=true
                ((FIXED_CHECKS++))
            else
                log_warn "$partition is a separate partition but not in fstab - manual configuration required"
            fi
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        local original=$(get_original_config "$rule_id")
        if [ -n "$original" ]; then
            # Find most recent backup
            local latest_backup=$(ls -t "$BACKUP_DIR"/fstab.* 2>/dev/null | head -1)
            if [ -n "$latest_backup" ]; then
                cp "$latest_backup" /etc/fstab
                log_info "Restored original fstab for $partition"
            fi
        fi
    fi
}

# Enhanced partition check that handles multiple options at once
check_partition_with_options() {
    local partition="$1"
    shift  # Remove first argument, rest are options
    local options=("$@")
    
    local rule_id="FS-PART-$(echo $partition | tr '/' '-' | tr '[:lower:]' '[:upper:]')-MULTI"
    local rule_name="Ensure security options set on $partition partition"
    
    if [ "$MODE" = "fix" ]; then
        # Check if partition exists first
        if [ ! -d "$partition" ]; then
            log_warn "Directory $partition does not exist - skipping"
            return 1
        fi
        
        # Determine if this is a tmpfs mount
        local is_tmpfs=false
        if [ "$partition" = "/tmp" ] || [ "$partition" = "/dev/shm" ]; then
            is_tmpfs=true
        fi
        
        # Build options string
        local opts_string=""
        for opt in "${options[@]}"; do
            if [ -z "$opts_string" ]; then
                opts_string="$opt"
            else
                opts_string="$opts_string,$opt"
            fi
        done
        
        # Check if partition already has an entry in fstab
        if fstab_has_entry "$partition"; then
            # Entry exists - ensure all options are present
            local modified=false
            for opt in "${options[@]}"; do
                if ! grep "^[^#]*[[:space:]]$partition[[:space:]]" /etc/fstab | grep -q "$opt"; then
                    sed -i "/^[^#]*[[:space:]]$partition[[:space:]]/s/\([[:space:]][^[:space:]]*[[:space:]][^[:space:]]*[[:space:]]\)\([^[:space:]]*\)/\1\2,$opt/" /etc/fstab
                    log_info "Added $opt to existing $partition entry in fstab"
                    modified=true
                fi
            done
            
            if [ "$modified" = "true" ]; then
                FSTAB_MODIFIED=true
                ((FIXED_CHECKS++))
            fi
        else
            # No entry exists - need to add one
            if [ "$FSTAB_MODIFIED" = "false" ]; then
                cp /etc/fstab "$BACKUP_DIR/fstab.$(date +%Y%m%d_%H%M%S)"
                log_info "Created fstab backup"
            fi
            
            if is_on_root_filesystem "$partition" && [ "$is_tmpfs" = "false" ]; then
                # Directory is on root filesystem - create bind mount
                log_info "$partition is on root filesystem - creating bind mount entry"
                
                echo "" >> /etc/fstab
                echo "# Bind mount for $partition with security options" >> /etc/fstab
                echo "$partition    $partition    none    defaults,bind,$opts_string    0 0" >> /etc/fstab
                
                log_info "Added bind mount entry for $partition with options: $opts_string"
                FSTAB_MODIFIED=true
                ((FIXED_CHECKS++))
                
            elif [ "$is_tmpfs" = "true" ]; then
                # This is a tmpfs mount
                log_info "$partition should be tmpfs - creating tmpfs entry"
                
                local size_opt=""
                if [ "$partition" = "/tmp" ]; then
                    size_opt=",size=2G"
                elif [ "$partition" = "/dev/shm" ]; then
                    size_opt=",size=1G"
                fi
                
                echo "" >> /etc/fstab
                echo "# Tmpfs mount for $partition with security options" >> /etc/fstab
                echo "tmpfs    $partition    tmpfs    defaults,$opts_string$size_opt    0 0" >> /etc/fstab
                
                log_info "Added tmpfs entry for $partition with options: $opts_string"
                FSTAB_MODIFIED=true
                ((FIXED_CHECKS++))
            fi
        fi
    fi
    
    # Always run individual checks for scan mode
    for opt in "${options[@]}"; do
        check_partition "$partition" "$opt"
    done
}

check_tmp_partition() {
    log_info "=== Checking /tmp Partition ==="
    
    local rule_id="FS-TMP-SEPARATE"
    local rule_name="Ensure /tmp is configured"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if mount | grep -q " on /tmp "; then
            log_pass "/tmp is mounted"
            ((PASSED_CHECKS++))
        else
            log_error "/tmp is not mounted"
            ((FAILED_CHECKS++))
        fi
    elif [ "$MODE" = "fix" ]; then
        if ! mount | grep -q " on /tmp "; then
            log_info "/tmp will be configured as tmpfs with security options"
        fi
    fi
    
    # Check/fix options
    if [ "$MODE" = "fix" ]; then
        check_partition_with_options "/tmp" "nodev" "nosuid" "noexec"
    else
        check_partition "/tmp" "nodev"
        check_partition "/tmp" "nosuid"
        check_partition "/tmp" "noexec"
    fi
}

check_dev_shm_partition() {
    log_info "=== Checking /dev/shm Partition ==="
    
    local rule_id="FS-DEVSHM-SEPARATE"
    local rule_name="Ensure /dev/shm is configured"
    
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
            log_info "/dev/shm will be configured as tmpfs with security options"
        fi
    fi
    
    # Check/fix options
    if [ "$MODE" = "fix" ]; then
        check_partition_with_options "/dev/shm" "nodev" "nosuid" "noexec"
    else
        check_partition "/dev/shm" "nodev"
        check_partition "/dev/shm" "nosuid"
        check_partition "/dev/shm" "noexec"
    fi
}

check_home_partition() {
    log_info "=== Checking /home Partition ==="
    
    local rule_id="FS-HOME-SEPARATE"
    local rule_name="Ensure /home is configured"
    
    ((TOTAL_CHECKS++))
    echo ""
    echo "Checking: $rule_name"
    echo "Rule ID: $rule_id"
    
    if [ "$MODE" = "scan" ]; then
        if mount | grep -q " on /home "; then
            if is_on_root_filesystem "/home"; then
                log_warn "/home is on root filesystem (bind mount recommended)"
            else
                log_pass "/home is a separate partition"
            fi
            ((PASSED_CHECKS++))
        else
            log_warn "/home is not separately mounted (recommended)"
            ((FAILED_CHECKS++))
        fi
    elif [ "$MODE" = "fix" ]; then
        if ! mount | grep -q " on /home "; then
            if is_on_root_filesystem "/home"; then
                log_info "/home is on root filesystem - will create bind mount"
            fi
        fi
    fi
    
    # Check/fix options
    if [ "$MODE" = "fix" ]; then
        check_partition_with_options "/home" "nodev" "nosuid"
    else
        if mount | grep -q " on /home " || [ -d "/home" ]; then
            check_partition "/home" "nodev"
            check_partition "/home" "nosuid"
        fi
    fi
}

check_var_partitions() {
    log_info "=== Checking /var Partitions ==="
    
    for part in "/var" "/var/tmp" "/var/log" "/var/log/audit"; do
        local part_clean=$(echo $part | tr '/' '-')
        local rule_id="FS-VAR${part_clean}-SEPARATE"
        local rule_name="Ensure $part is configured"
        
        ((TOTAL_CHECKS++))
        echo ""
        echo "Checking: $rule_name"
        echo "Rule ID: $rule_id"
        
        if [ "$MODE" = "scan" ]; then
            if mount | grep -q " on $part "; then
                if is_on_root_filesystem "$part"; then
                    log_warn "$part is on root filesystem (bind mount recommended)"
                else
                    log_pass "$part is a separate partition"
                fi
                ((PASSED_CHECKS++))
            else
                log_warn "$part is not separately mounted (recommended)"
                ((FAILED_CHECKS++))
            fi
        elif [ "$MODE" = "fix" ]; then
            if ! mount | grep -q " on $part "; then
                if [ -d "$part" ] && is_on_root_filesystem "$part"; then
                    log_info "$part is on root filesystem - will create bind mount"
                fi
            fi
        fi
        
        # Check/fix options based on directory
        if [ "$MODE" = "fix" ]; then
            if [ "$part" = "/var" ]; then
                check_partition_with_options "$part" "nodev" "nosuid"
            else
                check_partition_with_options "$part" "nodev" "nosuid" "noexec"
            fi
        else
            if mount | grep -q " on $part " || [ -d "$part" ]; then
                check_partition "$part" "nodev"
                check_partition "$part" "nosuid"
                if [ "$part" != "/var" ]; then
                    check_partition "$part" "noexec"
                fi
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
        
        # Apply all fstab changes at once if any were made
        if [ "$MODE" = "fix" ] && [ "$FSTAB_MODIFIED" = "true" ]; then
            echo ""
            log_info "========================================================================"
            log_info "Applying fstab changes..."
            log_info "========================================================================"
            
            if mount -a 2>/dev/null; then
                log_pass "Successfully applied all fstab changes (mount -a)"
            else
                log_error "Failed to apply some fstab changes - check /etc/fstab for errors"
                log_info "You can restore the backup from: $BACKUP_DIR"
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
            if [ "$FSTAB_MODIFIED" = "true" ]; then
                log_info "Fstab has been modified. Changes applied with 'mount -a'."
                log_info "Run 'scan' mode to verify all changes."
            else
                log_info "No fstab changes were necessary."
            fi
        fi
        
    elif [ "$MODE" = "rollback" ]; then
        log_info "Rolling back filesystem configurations..."
        
        # Rollback kernel modules
        for module in cramfs freevxfs hfs hfsplus jffs2 overlayfs squashfs udf usb-storage; do
            check_kernel_module "$module"
        done
        
        # Restore latest fstab backup
        local latest_backup=$(ls -t "$BACKUP_DIR"/fstab.* 2>/dev/null | head -1)
        if [ -n "$latest_backup" ]; then
            cp "$latest_backup" /etc/fstab
            log_info "Restored fstab from backup: $latest_backup"
            
            # Unmount bind mounts before remounting
            for part in /var/log/audit /var/log /var/tmp /var /home /tmp; do
                if mount | grep -q " on $part " && mount | grep " on $part " | grep -q "bind"; then
                    umount "$part" 2>/dev/null
                fi
            done
            
            mount -a 2>/dev/null
            log_info "Reapplied fstab mounts"
        fi
        
        log_info "Rollback completed"
    else
        echo "Usage: $0 {scan|fix|rollback}"
        exit 1
    fi
}

main
