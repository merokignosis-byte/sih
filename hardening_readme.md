# Linux Hardening Tool

A comprehensive Linux hardening tool with database-backed rollback capabilities for all 9 security topics from your Annexure.

## Features

- ✅ **Separate scanning for each rule** - Individual checks with detailed status
- ✅ **SQLite database** - Stores original configurations before any changes
- ✅ **Complete rollback support** - Restore previous settings anytime
- ✅ **Persistent state tracking** - Fixed rules stay fixed on subsequent scans
- ✅ **Text export** - All outputs saved to timestamped .txt files
- ✅ **Terminal-based** - No GUI, full terminal control
- ✅ **9 topic modules** - Separate bash scripts for each security topic
- ✅ **Audit trail** - Complete history of all changes

## Directory Structure

```
linux-hardening-tool/
├── hardening_controller.py       # Main Python controller
├── hardening.db                   # SQLite database (auto-created)
├── hardening_scripts/
│   ├── 01_filesystem.sh
│   ├── 02_package_management.sh
│   ├── 03_services.sh
│   ├── 04_network.sh
│   ├── 05_firewall.sh
│   ├── 06_access_control.sh
│   ├── 07_user_accounts.sh
│   ├── 08_logging_auditing.sh
│   └── 09_system_maintenance.sh
├── output/                        # Generated reports
└── backups/                       # Configuration backups
```

## Installation

```bash
# 1. Create directory structure
mkdir -p linux-hardening-tool/{hardening_scripts,output,backups}
cd linux-hardening-tool

# 2. Copy the Python controller script
# Save hardening_controller.py to this directory

# 3. Copy all bash scripts to hardening_scripts/
# Save all 9 bash scripts to hardening_scripts/

# 4. Make scripts executable
chmod +x hardening_controller.py
chmod +x hardening_scripts/*.sh

# 5. Install required dependencies (if needed)
apt-get update
apt-get install -y python3 sqlite3
```

## Usage

### Interactive Mode (Recommended)

```bash
sudo ./hardening_controller.py
```

This launches an interactive menu where you can:
- Scan individual topics
- Fix issues in specific topics
- Rollback changes
- View status reports
- Export comprehensive reports

### Command-Line Mode

```bash
# Scan all topics
sudo ./hardening_controller.py scan-all

# Generate report
sudo ./hardening_controller.py report
```

### Direct Script Execution

```bash
# Scan a specific topic
sudo bash hardening_scripts/01_filesystem.sh scan

# Fix issues in a topic
sudo bash hardening_scripts/01_filesystem.sh fix

# Rollback changes
sudo bash hardening_scripts/01_filesystem.sh rollback
```

## Workflow

### 1. Initial Scan
```bash
sudo ./hardening_controller.py
# Choose: scan
# Choose topic: 1
```

This will:
- Check all filesystem rules
- Display PASS/FAIL for each rule
- Save output to `output/Filesystem_scan_TIMESTAMP.txt`
- Show summary with pass/fail counts

### 2. Fix Issues
```bash
# From menu: fix
# Choose topic: 1
```

This will:
- Save original configurations to database BEFORE making changes
- Apply fixes for failed rules
- Display what was changed
- Save output to `output/Filesystem_fix_TIMESTAMP.txt`

### 3. Verify Fix
```bash
# From menu: scan
# Choose topic: 1
```

Rules that were successfully fixed will now show as **PASS** instead of FAIL.

### 4. Rollback (if needed)
```bash
# From menu: rollback
# Choose topic: 1
# Confirm: yes
```

This will:
- Restore original configurations from database
- Revert all changes made by fix
- Save output to `output/Filesystem_rollback_TIMESTAMP.txt`

## Output Files

All operations generate timestamped output files in `output/`:

```
output/
├── Filesystem_scan_20241123_143022.txt
├── Filesystem_fix_20241123_143155.txt
├── Network_scan_20241123_144311.txt
├── hardening_report_20241123_150000.txt
└── ...
```

Each file contains:
- Timestamp
- Topic name
- Mode (scan/fix/rollback)
- Detailed results for each rule
- Summary statistics

## Database Schema

### configurations table
```sql
- id: Primary key
- topic: Security topic (e.g., "Filesystem")
- rule_id: Unique rule identifier (e.g., "FS-KM-CRAMFS")
- rule_name: Human-readable rule name
- original_value: Configuration before fix
- current_value: Configuration after fix
- timestamp: When saved
- status: original/stored/fixed
```

### audit_log table
```sql
- id: Primary key
- topic: Security topic
- rule_id: Rule identifier
- action: scan/fix/rollback
- old_value: Previous value
- new_value: New value
- timestamp: When action occurred
- success: Boolean
```

## Key Features Explained

### 1. Persistent State Tracking
Once a rule is fixed, it stays fixed. On subsequent scans, the tool checks the *actual current state*, not just whether it was previously fixed.

**Example:**
```
First scan:  FS-KM-CRAMFS → FAIL (module not blacklisted)
After fix:   FS-KM-CRAMFS → Database stores original state
Second scan: FS-KM-CRAMFS → PASS (module is blacklisted)
```

### 2. Complete Rollback
The database stores the exact original configuration before any changes:

```python
# Before fix
save_config("FS-KM-CRAMFS", "Ensure cramfs disabled", "not_blacklisted")

# During rollback
original = get_original_config("FS-KM-CRAMFS")
# Restores: "not_blacklisted" → removes blacklist file
```

### 3. Individual Rule Checks
Each rule has its own check function that:
- Verifies current state (not database state)
- Returns actual PASS/FAIL based on system configuration
- Updates counters independently

### 4. Detailed Terminal Output
Every operation shows:
```
======================================================================
Topic: Filesystem
Mode: SCAN
Output: output/Filesystem_scan_20241123_143022.txt
======================================================================

Checking: Ensure cramfs kernel module is not available
Rule ID: FS-KM-CRAMFS
[FAIL] Module cramfs is not blacklisted

Checking: Ensure freevxfs kernel module is not available
Rule ID: FS-KM-FREEVXFS
[PASS] Module freevxfs is properly disabled

...

======================================================================
Summary
======================================================================
Total Checks: 25
Passed: 18
Failed: 7
```

## All 9 Topics

1. **Filesystem** - Kernel modules, partition options, mount points
2. **Package Management** - Bootloader, process hardening, banners
3. **Services** - Server and client services configuration
4. **Network** - Network devices, kernel parameters, IP forwarding
5. **Host Based Firewall** - UFW/iptables configuration
6. **Access Control** - SSH, sudo, PAM modules
7. **User Accounts** - Password policies, account settings
8. **Logging and Auditing** - rsyslog, auditd, log rotation
9. **System Maintenance** - File permissions, duplicate checks

## Troubleshooting

### "Must be run as root"
```bash
sudo ./hardening_controller.py
```

### Scripts not executable
```bash
chmod +x hardening_controller.py hardening_scripts/*.sh
```

### Database locked
```bash
# Stop all running instances
pkill -f hardening_controller.py
```

### Rollback not working
- Check database for stored configurations
- Verify backup files exist in `backups/` directory
- Check file permissions

## Security Notes

⚠️ **Important:**
- Always test in a non-production environment first
- Some fixes require system reboot to take full effect
- Partition changes may require manual intervention
- Review rollback operations before confirming

## Complete Script List

All 9 hardening scripts are now complete:

1. ✅ **01_filesystem.sh** - Kernel modules, partitions, mount options
2. ✅ **02_package_management.sh** - Bootloader, process hardening, banners
3. ✅ **03_services.sh** - Server/client services, time sync, cron
4. ✅ **04_network.sh** - Network devices, kernel modules, sysctl parameters
5. ✅ **05_firewall.sh** - UFW configuration and firewall rules
6. ✅ **06_access_control.sh** - SSH, sudo, PAM, authentication
7. ✅ **07_user_accounts.sh** - Password policies, user environment
8. ✅ **08_logging_auditing.sh** - journald, rsyslog, auditd, AIDE
9. ✅ **09_system_maintenance.sh** - File permissions, duplicate checks

## Quick Start

```bash
# 1. Setup
mkdir -p linux-hardening-tool/hardening_scripts
cd linux-hardening-tool

# 2. Place all scripts in correct locations
# - hardening_controller.py in root directory
# - All 9 .sh scripts in hardening_scripts/

# 3. Make executable
chmod +x hardening_controller.py hardening_scripts/*.sh

# 4. Run initial scan
sudo ./hardening_controller.py
# Choose: scan, then topic: 1 (or 'all' for all topics)

# 5. Review output files in output/ directory

# 6. Apply fixes
sudo ./hardening_controller.py
# Choose: fix, then topic: 1

# 7. Verify fixes
sudo ./hardening_controller.py
# Choose: scan, then topic: 1 (should show PASS for fixed items)

# 8. If needed, rollback
sudo ./hardening_controller.py
# Choose: rollback, then topic: 1, confirm: yes
```

## Example Session

```bash
$ sudo ./hardening_controller.py

======================================================================
Linux Hardening Tool - Main Menu
======================================================================

Topics:
  1. Filesystem
  2. Package Management
  3. Services
  4. Network
  5. Host Based Firewall
  6. Access Control
  7. User Accounts
  8. Logging and Auditing
  9. System Maintenance

Actions:
  scan   - Scan a topic
  fix    - Fix issues in a topic
  rollback - Rollback fixes for a topic
  status - Show hardening status
  report - Export comprehensive report
  all    - Scan all topics
  quit   - Exit

Enter your choice: scan
Enter topic ID: 1

========================================================================
Filesystem Hardening Script
Mode: scan
========================================================================

Checking: Ensure cramfs kernel module is not available
Rule ID: FS-KM-CRAMFS
[FAIL] Module cramfs is not blacklisted

Checking: Ensure /tmp is a separate partition
Rule ID: FS-TMP-SEPARATE
[PASS] /tmp is a separate partition

...

========================================================================
Summary
========================================================================
Total Checks: 25
Passed: 18
Failed: 7

[WARN] 7 checks failed. Run with 'fix' mode to remediate.

[INFO] Output saved to: output/Filesystem_scan_20241123_143022.txt
```

## Features Explained

### 1. Database-Backed Rollback
Every fix operation saves the original configuration to SQLite:
```sql
sqlite3 hardening.db "SELECT * FROM configurations WHERE topic='Filesystem';"
```

### 2. Persistent State Tracking
Fixed rules stay fixed! The tool checks actual system state, not just database records:
```bash
# First scan: Shows FAIL
# After fix: Saves original to DB
# Second scan: Checks actual system → Shows PASS (because it's actually fixed)
# Manual break: User manually reverts the fix
# Third scan: Shows FAIL again (detects the manual change)
```

### 3. Comprehensive Audit Trail
```sql
sqlite3 hardening.db "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 10;"
```

### 4. Export Everything
All operations create timestamped .txt files:
```bash
ls -lh output/
-rw-r--r-- 1 root root 12K Nov 23 14:30 Filesystem_scan_20241123_143022.txt
-rw-r--r-- 1 root root  8K Nov 23 14:35 Filesystem_fix_20241123_143515.txt
-rw-r--r-- 1 root root 45K Nov 23 15:00 hardening_report_20241123_150000.txt
```

## Testing the Tool

### Test Scenario 1: Basic Scan and Fix
```bash
# Scan filesystem
sudo ./hardening_controller.py
> scan
> 1

# Apply fixes
sudo ./hardening_controller.py
> fix
> 1

# Verify (should show more PASS than before)
sudo ./hardening_controller.py
> scan
> 1
```

### Test Scenario 2: Rollback
```bash
# After fixing, rollback
sudo ./hardening_controller.py
> rollback
> 1
> yes

# Scan again (should show FAIL for rolled-back items)
sudo ./hardening_controller.py
> scan
> 1
```

### Test Scenario 3: Generate Report
```bash
sudo ./hardening_controller.py
> report

# View report
cat output/hardening_report_*.txt
```

## Important Notes

### Requires Root
All operations require root privileges:
```bash
sudo ./hardening_controller.py
```

### Some Fixes Need Reboot
- Kernel parameter changes
- Bootloader modifications
- Some service changes

### Manual Review Required
Some checks require manual intervention:
- Bootloader password setup
- Firewall rule configuration for specific services
- Review of SUID/SGID files
- Resolution of duplicate UIDs/GIDs

### Backup Everything
Before running in production:
```bash
# Backup critical files
tar czf system-backup-$(date +%Y%m%d).tar.gz \
  /etc/ssh/sshd_config \
  /etc/sysctl.conf \
  /etc/fstab \
  /etc/pam.d/ \
  /etc/security/
```

## Troubleshooting

### Issue: "Database is locked"
```bash
# Kill any running instances
pkill -f hardening_controller.py

# Check for locks
lsof hardening.db
```

### Issue: "Permission denied"
```bash
# Ensure running as root
sudo ./hardening_controller.py

# Check script permissions
chmod +x hardening_controller.py hardening_scripts/*.sh
```

### Issue: "Script not found"
```bash
# Verify directory structure
ls -la hardening_scripts/
# Should show all 9 .sh files

# Check paths in controller
python3 -c "from pathlib import Path; print(Path.cwd())"
```

### Issue: "Module not found (sqlite3)"
```bash
# Install Python SQLite
apt-get install python3-sqlite3

# Or use system Python
/usr/bin/python3 hardening_controller.py
```

## Best Practices

1. **Test in staging first** - Never run on production without testing
2. **Scan before fixing** - Always scan first to see what will change
3. **One topic at a time** - Start with least critical (like logging)
4. **Review output files** - Always check the generated .txt files
5. **Keep backups** - Database stores configs, but keep separate backups
6. **Document exceptions** - Note any manual configurations needed
7. **Schedule regular scans** - Add to cron for ongoing compliance

## Customization

### Add Custom Rules
Edit the appropriate script and add new check functions:
```bash
check_custom_rule() {
    local rule_id="CUSTOM-RULE-001"
    local rule_name="My custom security check"
    # ... implementation
}
```

### Modify Expected Values
Change expected values in the scripts:
```bash
# Example: Change PASS_MAX_DAYS from 365 to 90
check_login_defs_param "PASS_MAX_DAYS" "90"  # was "365"
```

### Exclude Specific Checks
Comment out checks you don't want:
```bash
# check_kernel_module "usb-storage"  # Disabled - USB needed
```

## Support

For issues or questions:
1. Check the output .txt files for detailed error messages
2. Review the database: `sqlite3 hardening.db`
3. Check system logs: `journalctl -xe`
4. Verify prerequisites: Python 3, SQLite, root access
