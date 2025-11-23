#!/usr/bin/env python3
"""
Linux Hardening Tool - Installation Script (Python)
Perfect logic with proper error handling and file management
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path

# Color codes
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
NC = '\033[0m'

def log_info(msg):
    print(f"{GREEN}[INFO]{NC} {msg}")

def log_warn(msg):
    print(f"{YELLOW}[WARN]{NC} {msg}")

def log_error(msg):
    print(f"{RED}[ERROR]{NC} {msg}")

def log_success(msg):
    print(f"{GREEN}[SUCCESS]{NC} {msg}")

def check_root():
    """Check if running as root"""
    if os.geteuid() != 0:
        log_error("This script must be run as root!")
        log_info("Please use: sudo python3 install.py")
        sys.exit(1)

def check_prerequisites():
    """Check and install prerequisites"""
    log_info("Checking prerequisites...")
    
    # Check Python 3
    if sys.version_info < (3, 6):
        log_error("Python 3.6 or higher is required!")
        sys.exit(1)
    log_info(f"Python version: {sys.version_info.major}.{sys.version_info.minor}")
    
    # Check SQLite
    try:
        import sqlite3
        log_info("SQLite3: Available")
    except ImportError:
        log_warn("Installing Python SQLite3...")
        subprocess.run(['apt-get', 'update'], check=False)
        subprocess.run(['apt-get', 'install', '-y', 'python3-sqlite3'], check=False)

def create_directory_structure():
    """Create all necessary directories"""
    log_info("Creating directory structure...")
    
    base_dir = Path.cwd()
    
    directories = [
        base_dir / "hardening_scripts",
        base_dir / "output",
        base_dir / "backups",
        base_dir / "backups" / "filesystem",
        base_dir / "backups" / "package_management",
        base_dir / "backups" / "services",
        base_dir / "backups" / "network",
        base_dir / "backups" / "firewall",
        base_dir / "backups" / "access_control",
        base_dir / "backups" / "user_accounts",
        base_dir / "backups" / "logging_auditing",
        base_dir / "backups" / "system_maintenance"
    ]
    
    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)
        log_info(f"Created/verified: {directory.name}/")
    
    return base_dir

def copy_hardening_scripts(base_dir):
    """Copy all hardening scripts to hardening_scripts directory"""
    log_info("Checking and copying hardening scripts...")
    
    scripts = [
        "filesystem.sh",
        "package_mgmt.sh",
        "services.sh",
        "network.sh",
        "firewall.sh",
        "access_control.sh",
        "user_accounts.sh",
        "logging_auditing.sh",
        "system_maintenance.sh"
    ]
    
    source_dir = base_dir
    dest_dir = base_dir / "hardening_scripts"
    
    copied = 0
    already_exists = 0
    missing = []
    
    print()
    for script in scripts:
        source_file = source_dir / script
        dest_file = dest_dir / script
        
        # Check if already in destination
        if dest_file.exists():
            log_info(f"✓ Already exists: {script}")
            already_exists += 1
            continue
        
        # Check if in source directory
        if source_file.exists():
            try:
                shutil.copy2(source_file, dest_file)
                os.chmod(dest_file, 0o755)  # Make executable
                log_success(f"✓ Copied: {script} → hardening_scripts/")
                copied += 1
            except Exception as e:
                log_error(f"✗ Failed to copy {script}: {e}")
                missing.append(script)
        else:
            log_warn(f"✗ Not found: {script}")
            missing.append(script)
    
    print()
    print("="*70)
    log_info(f"Script Summary:")
    print(f"  Copied: {copied}")
    print(f"  Already present: {already_exists}")
    print(f"  Missing: {len(missing)}")
    print("="*70)
    print()
    
    if missing:
        log_warn(f"Missing {len(missing)} script(s):")
        for script in missing:
            print(f"  - {script}")
        print()
        log_warn("Place missing scripts in the current directory and run install again")
        print()
    
    return len(missing)

def set_permissions(base_dir):
    """Set executable permissions on scripts"""
    log_info("Setting permissions...")
    
    # Make controller executable
    controller = base_dir / "hardening_controller.py"
    if controller.exists():
        os.chmod(controller, 0o755)
        log_info("Set executable: hardening_controller.py")
    
    # Make all scripts in hardening_scripts executable
    scripts_dir = base_dir / "hardening_scripts"
    if scripts_dir.exists():
        for script_file in scripts_dir.glob("*.sh"):
            os.chmod(script_file, 0o755)
        log_info("Set executable: all .sh files in hardening_scripts/")

def create_config_file(base_dir):
    """Create sample configuration file"""
    log_info("Creating configuration file...")
    
    config_content = """# Linux Hardening Tool Configuration
# This file is for reference only

# Database location
DB_PATH=./hardening.db

# Output directory
OUTPUT_DIR=./output

# Backup directory
BACKUP_DIR=./backups

# Log level (INFO, WARN, ERROR)
LOG_LEVEL=INFO
"""
    
    config_file = base_dir / "config.txt"
    with open(config_file, 'w') as f:
        f.write(config_content)
    
    log_info(f"Created: config.txt")

def initialize_database(base_dir):
    """Initialize SQLite database"""
    log_info("Initializing database...")
    
    import sqlite3
    
    db_path = base_dir / "hardening.db"
    
    # Remove old database if exists
    if db_path.exists():
        log_info("Removing old database...")
        db_path.unlink()
    
    # Create new database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Configurations table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS configurations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            topic TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            rule_name TEXT NOT NULL,
            original_value TEXT,
            current_value TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'original',
            UNIQUE(topic, rule_id)
        )
    ''')
    
    # Audit log table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            topic TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            action TEXT NOT NULL,
            old_value TEXT,
            new_value TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            success INTEGER DEFAULT 1
        )
    ''')
    
    conn.commit()
    conn.close()
    
    log_success("Database initialized successfully")

def create_quickstart_guide(base_dir):
    """Create quick start guide"""
    log_info("Creating quick start guide...")
    
    quickstart_content = """# Quick Start Guide

## First Time Setup

1. **Initial Scan (Recommended)**
   ```bash
   sudo ./hardening_controller.py
   > scan
   > 1
   ```
   This scans the Filesystem topic and shows current status.

2. **Review Output**
   ```bash
   cat output/Filesystem_scan_*.txt
   ```
   Check what failed and what passed.

3. **Apply Fixes**
   ```bash
   sudo ./hardening_controller.py
   > fix
   > 1
   ```
   This fixes the issues found in step 1.

4. **Verify**
   ```bash
   sudo ./hardening_controller.py
   > scan
   > 1
   ```
   Confirm fixes were applied (should show more PASS).

5. **Scan All Topics**
   ```bash
   sudo ./hardening_controller.py
   > all
   ```
   Scan all 9 security topics at once.

## Common Tasks

### Generate Full Report
```bash
sudo ./hardening_controller.py
> report
```

### Check Status
```bash
sudo ./hardening_controller.py
> status
```

### Rollback Topic
```bash
sudo ./hardening_controller.py
> rollback
> 1
> yes
```

### Command Line Mode
```bash
# Scan all topics
sudo ./hardening_controller.py scan-all

# Generate report
sudo ./hardening_controller.py report
```

## Topic Numbers

1. Filesystem
2. Package Management
3. Services
4. Network
5. Host Based Firewall
6. Access Control
7. User Accounts
8. Logging and Auditing
9. System Maintenance

## Important Notes

- Always run as root (sudo)
- Test in staging before production
- Some changes require reboot
- Keep database backups
- Review output files regularly
"""
    
    quickstart_file = base_dir / "QUICKSTART.md"
    with open(quickstart_file, 'w') as f:
        f.write(quickstart_content)
    
    log_info("Created: QUICKSTART.md")

def create_wrapper_script(base_dir):
    """Create wrapper script for easy access"""
    log_info("Creating wrapper script...")
    
    wrapper_content = """#!/bin/bash
# Wrapper script for Linux Hardening Tool

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] This tool must be run as root!"
    exit 1
fi

cd "$SCRIPT_DIR"
exec python3 hardening_controller.py "$@"
"""
    
    wrapper_file = base_dir / "hardening"
    with open(wrapper_file, 'w') as f:
        f.write(wrapper_content)
    
    os.chmod(wrapper_file, 0o755)
    log_info("Created: hardening (wrapper script)")

def test_installation(base_dir):
    """Test the installation"""
    log_info("Testing installation...")
    
    controller = base_dir / "hardening_controller.py"
    
    if not controller.exists():
        log_warn("hardening_controller.py not found!")
        return False
    
    try:
        result = subprocess.run(
            ['python3', str(controller), '--help'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if 'scan-all' in result.stdout or 'Usage' in result.stdout:
            log_success("Controller test: PASSED")
            return True
        else:
            log_warn("Controller test: Could not verify")
            return False
    except Exception as e:
        log_warn(f"Controller test: {e}")
        return False

def print_final_summary(base_dir, missing_count):
    """Print installation summary"""
    print()
    print("="*70)
    log_success("Installation Complete!")
    print("="*70)
    print()
    
    print("File Structure:")
    print(f"  {BLUE}./hardening_controller.py{NC}  - Main controller")
    print(f"  {BLUE}./hardening{NC}                - Wrapper script")
    print(f"  {BLUE}./install.py{NC}               - This installation script")
    print(f"  {BLUE}./hardening_scripts/{NC}       - All hardening scripts")
    print(f"  {BLUE}./output/{NC}                  - Scan/fix output files")
    print(f"  {BLUE}./backups/{NC}                 - Backup files")
    print(f"  {BLUE}./hardening.db{NC}             - SQLite database")
    print(f"  {BLUE}./config.txt{NC}               - Configuration reference")
    print(f"  {BLUE}./QUICKSTART.md{NC}            - Quick start guide")
    print()
    
    if missing_count == 0:
        log_success("All scripts are present and ready!")
        print()
        print("Next steps:")
        print()
        print(f"  1. Run your first scan:")
        print(f"     {GREEN}sudo ./hardening_controller.py{NC}")
        print(f"     or")
        print(f"     {GREEN}sudo ./hardening{NC}")
        print()
    else:
        print("="*70)
        log_warn(f"WARNING: {missing_count} script(s) are missing!")
        log_warn("Please add all 9 hardening scripts to the current directory")
        log_warn("then run: sudo python3 install.py")
        print("="*70)
        print()
    
    log_info("Happy hardening! 🔒")
    print()

def main():
    """Main installation function"""
    print("="*70)
    print("Linux Hardening Tool - Installation (Python)")
    print("="*70)
    print()
    
    # Check root
    check_root()
    
    # Check if controller exists
    if not Path("hardening_controller.py").exists():
        log_error("hardening_controller.py not found!")
        log_error("Please run this script from the directory containing all tool files")
        sys.exit(1)
    
    # Prerequisites
    check_prerequisites()
    
    # Create directories
    base_dir = create_directory_structure()
    
    # Copy scripts
    missing_count = copy_hardening_scripts(base_dir)
    
    # Set permissions
    set_permissions(base_dir)
    
    # Create config
    create_config_file(base_dir)
    
    # Initialize database
    initialize_database(base_dir)
    
    # Create guides
    create_quickstart_guide(base_dir)
    
    # Create wrapper
    create_wrapper_script(base_dir)
    
    # Test installation
    test_installation(base_dir)
    
    # Print summary
    print_final_summary(base_dir, missing_count)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[INFO] Installation cancelled by user")
        sys.exit(1)
    except Exception as e:
        log_error(f"Installation failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
