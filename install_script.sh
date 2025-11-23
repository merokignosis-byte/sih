#!/bin/bash
# Linux Hardening Tool - Installation Script

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

echo "=========================================================================="
echo "Linux Hardening Tool - Installation"
echo "=========================================================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    log_error "This script must be run as root!"
    exit 1
fi

# Check if we're in the right directory
if [ ! -f "hardening_controller.py" ]; then
    log_error "hardening_controller.py not found!"
    log_error "Please run this script from the directory containing all tool files"
    exit 1
fi

log_info "Checking prerequisites..."

# Check Python 3
if ! command -v python3 &> /dev/null; then
    log_warn "Python 3 not found. Installing..."
    apt-get update
    apt-get install -y python3
fi

# Check SQLite
if ! python3 -c "import sqlite3" 2>/dev/null; then
    log_warn "Python SQLite3 not found. Installing..."
    apt-get install -y python3-sqlite3
fi

log_info "Creating directory structure..."

# Create directories
mkdir -p hardening_scripts
mkdir -p output
mkdir -p backups/{filesystem,package_management,services,network,firewall,access_control,user_accounts,logging_auditing,system_maintenance}

log_info "Setting permissions..."

# Make controller executable
chmod +x hardening_controller.py

# Make all scripts executable
if [ -d "hardening_scripts" ]; then
    chmod +x hardening_scripts/*.sh 2>/dev/null || true
fi

# Check for script files
log_info "Checking for hardening scripts..."

SCRIPTS=(
    "01_filesystem.sh"
    "02_package_management.sh"
    "03_services.sh"
    "04_network.sh"
    "05_firewall.sh"
    "06_access_control.sh"
    "07_user_accounts.sh"
    "08_logging_auditing.sh"
    "09_system_maintenance.sh"
)

MISSING_SCRIPTS=0
for script in "${SCRIPTS[@]}"; do
    if [ ! -f "hardening_scripts/$script" ]; then
        log_warn "Missing: hardening_scripts/$script"
        ((MISSING_SCRIPTS++))
    else
        log_info "Found: $script"
    fi
done

if [ $MISSING_SCRIPTS -gt 0 ]; then
    echo ""
    log_warn "$MISSING_SCRIPTS script(s) are missing!"
    log_warn "Please ensure all 9 hardening scripts are in hardening_scripts/ directory"
    echo ""
fi

# Create a sample configuration file
cat > config.txt << 'EOF'
# Linux Hardening Tool Configuration
# This file is for reference only

# Database location
DB_PATH=./hardening.db

# Output directory
OUTPUT_DIR=./output

# Backup directory
BACKUP_DIR=./backups

# Log level (INFO, WARN, ERROR)
LOG_LEVEL=INFO
EOF

log_info "Configuration file created: config.txt"

# Initialize the database
log_info "Initializing database..."
python3 << 'PYEOF'
import sqlite3
import os

db_path = "hardening.db"

# Remove old database if exists
if os.path.exists(db_path):
    print(f"[INFO] Removing old database: {db_path}")
    os.remove(db_path)

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

print("[INFO] Database initialized successfully")
PYEOF

# Create a quick start guide
cat > QUICKSTART.md << 'EOF'
# Quick Start Guide

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
EOF

log_info "Quick start guide created: QUICKSTART.md"

# Test the installation
log_info "Testing installation..."

if python3 hardening_controller.py --help 2>/dev/null | grep -q "scan-all"; then
    log_info "Controller test: OK"
else
    log_warn "Controller test: Could not verify"
fi

# Create wrapper script for easy access
cat > hardening << 'EOF'
#!/bin/bash
# Wrapper script for Linux Hardening Tool

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] This tool must be run as root!"
    exit 1
fi

cd "$SCRIPT_DIR"
exec python3 hardening_controller.py "$@"
EOF

chmod +x hardening

log_info "Wrapper script created: ./hardening"

echo ""
echo "=========================================================================="
log_info "Installation complete!"
echo "=========================================================================="
echo ""
echo "Next steps:"
echo ""
echo "  1. Verify all scripts are present:"
echo "     ${BLUE}ls -lh hardening_scripts/${NC}"
echo ""
echo "  2. Run your first scan:"
echo "     ${GREEN}sudo ./hardening_controller.py${NC}"
echo "     or"
echo "     ${GREEN}sudo ./hardening${NC}"
echo ""
echo "  3. Read the quick start guide:"
echo "     ${BLUE}cat QUICKSTART.md${NC}"
echo ""
echo "  4. Check full documentation:"
echo "     ${BLUE}cat README.md${NC}"
echo ""

if [ $MISSING_SCRIPTS -gt 0 ]; then
    echo "=========================================================================="
    log_warn "WARNING: $MISSING_SCRIPTS script(s) are missing!"
    log_warn "Please add all 9 hardening scripts before running the tool."
    echo "=========================================================================="
    echo ""
fi

log_info "Happy hardening! 🔒"
