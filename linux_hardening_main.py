#!/usr/bin/env python3
"""
Linux Hardening Tool - Main Controller
Supports scanning, fixing, and rollback with SQLite database
"""

import os
import sys
import sqlite3
import json
import subprocess
import datetime
from pathlib import Path

class HardeningController:
    def __init__(self):
        self.base_dir = Path(__file__).parent
        self.db_path = self.base_dir / "hardening.db"
        self.scripts_dir = self.base_dir / "hardening_scripts"
        self.output_dir = self.base_dir / "output"
        self.output_dir.mkdir(exist_ok=True)
        
        self.topics = {
            "1": {"name": "Filesystem", "script": "filesystem.sh"},
            "2": {"name": "Package Management", "script": "package_mgmt.sh"},
            "3": {"name": "Services", "script": "services.sh"},
            "4": {"name": "Network", "script": "network.sh"},
            "5": {"name": "Host Based Firewall", "script": "firewall.sh"},
            "6": {"name": "Access Control", "script": "access_control.sh"},
            "7": {"name": "User Accounts", "script": "user_accounts.sh"},
            "8": {"name": "Logging and Auditing", "script": "logging_auditing.sh"},
            "9": {"name": "System Maintenance", "script": "system_maintenance.sh"}
        }
        
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database for storing configurations"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Table for storing original configurations before fixes
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
        
        # Table for audit trail
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
    
    def save_config(self, topic, rule_id, rule_name, original_value, current_value=None):
        """Save configuration before applying fix"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO configurations 
                (topic, rule_id, rule_name, original_value, current_value, status)
                VALUES (?, ?, ?, ?, ?, 'stored')
            ''', (topic, rule_id, rule_name, original_value, current_value or original_value))
            conn.commit()
            return True
        except Exception as e:
            print(f"[ERROR] Failed to save config: {e}")
            return False
        finally:
            conn.close()
    
    def log_action(self, topic, rule_id, action, old_value, new_value, success=True):
        """Log actions in audit trail"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO audit_log (topic, rule_id, action, old_value, new_value, success)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (topic, rule_id, action, old_value, new_value, 1 if success else 0))
        
        conn.commit()
        conn.close()
    
    def run_script(self, topic_id, mode):
        """Run hardening script in specified mode"""
        if topic_id not in self.topics:
            print(f"[ERROR] Invalid topic ID: {topic_id}")
            return None
        
        topic = self.topics[topic_id]
        script_path = self.scripts_dir / topic["script"]
        
        if not script_path.exists():
            print(f"[ERROR] Script not found: {script_path}")
            return None
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = self.output_dir / f"{topic['name'].replace(' ', '_')}_{mode}_{timestamp}.txt"
        
        print(f"\n{'='*70}")
        print(f"Topic: {topic['name']}")
        print(f"Mode: {mode.upper()}")
        print(f"Output: {output_file}")
        print(f"{'='*70}\n")
        
        try:
            # Run script with mode parameter
            result = subprocess.run(
                ['bash', str(script_path), mode],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            # Display output in terminal
            print(result.stdout)
            if result.stderr:
                print(f"[STDERR]\n{result.stderr}")
            
            # Save output to file
            with open(output_file, 'w') as f:
                f.write(f"Topic: {topic['name']}\n")
                f.write(f"Mode: {mode}\n")
                f.write(f"Timestamp: {timestamp}\n")
                f.write(f"{'='*70}\n\n")
                f.write(result.stdout)
                if result.stderr:
                    f.write(f"\n\n[STDERR]\n{result.stderr}")
            
            print(f"\n[INFO] Output saved to: {output_file}")
            return result.returncode == 0
            
        except subprocess.TimeoutExpired:
            print(f"[ERROR] Script execution timed out")
            return False
        except Exception as e:
            print(f"[ERROR] Failed to execute script: {e}")
            return False
    
    def rollback_topic(self, topic_id):
        """Rollback all fixes for a specific topic"""
        if topic_id not in self.topics:
            print(f"[ERROR] Invalid topic ID: {topic_id}")
            return False
        
        topic = self.topics[topic_id]
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT rule_id, rule_name, original_value, current_value 
            FROM configurations 
            WHERE topic = ?
        ''', (topic['name'],))
        
        configs = cursor.fetchall()
        conn.close()
        
        if not configs:
            print(f"[INFO] No configurations to rollback for {topic['name']}")
            return True
        
        print(f"\n{'='*70}")
        print(f"Rollback: {topic['name']}")
        print(f"{'='*70}\n")
        
        # Run rollback script
        return self.run_script(topic_id, 'rollback')
    
    def show_status(self, topic_id=None):
        """Show current hardening status"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if topic_id:
            if topic_id not in self.topics:
                print(f"[ERROR] Invalid topic ID: {topic_id}")
                conn.close()
                return
            
            topic = self.topics[topic_id]
            cursor.execute('''
                SELECT rule_id, rule_name, status, timestamp 
                FROM configurations 
                WHERE topic = ?
                ORDER BY rule_id
            ''', (topic['name'],))
            
            print(f"\n{'='*70}")
            print(f"Status: {topic['name']}")
            print(f"{'='*70}\n")
        else:
            cursor.execute('''
                SELECT topic, COUNT(*) as count, 
                       SUM(CASE WHEN status = 'fixed' THEN 1 ELSE 0 END) as fixed
                FROM configurations 
                GROUP BY topic
            ''')
            
            print(f"\n{'='*70}")
            print(f"Overall Hardening Status")
            print(f"{'='*70}\n")
        
        results = cursor.fetchall()
        
        if not results:
            print("[INFO] No configurations found in database")
        else:
            for row in results:
                print(f"  {row}")
        
        conn.close()
    
    def export_report(self):
        """Export comprehensive report"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = self.output_dir / f"hardening_report_{timestamp}.txt"
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        with open(report_file, 'w') as f:
            f.write("="*70 + "\n")
            f.write("Linux Hardening Report\n")
            f.write(f"Generated: {timestamp}\n")
            f.write("="*70 + "\n\n")
            
            # Summary
            cursor.execute('''
                SELECT topic, COUNT(*) as total,
                       SUM(CASE WHEN status = 'fixed' THEN 1 ELSE 0 END) as fixed
                FROM configurations
                GROUP BY topic
            ''')
            
            f.write("SUMMARY\n")
            f.write("-"*70 + "\n")
            for row in cursor.fetchall():
                f.write(f"{row[0]}: {row[2]}/{row[1]} fixed\n")
            
            # Detailed configurations
            f.write("\n\nDETAILED CONFIGURATIONS\n")
            f.write("-"*70 + "\n\n")
            
            cursor.execute('''
                SELECT topic, rule_id, rule_name, original_value, current_value, status, timestamp
                FROM configurations
                ORDER BY topic, rule_id
            ''')
            
            for row in cursor.fetchall():
                f.write(f"Topic: {row[0]}\n")
                f.write(f"Rule ID: {row[1]}\n")
                f.write(f"Rule Name: {row[2]}\n")
                f.write(f"Original: {row[3]}\n")
                f.write(f"Current: {row[4]}\n")
                f.write(f"Status: {row[5]}\n")
                f.write(f"Timestamp: {row[6]}\n")
                f.write("-"*70 + "\n")
        
        conn.close()
        print(f"\n[INFO] Report exported to: {report_file}")
    
    def display_menu(self):
        """Display interactive menu"""
        while True:
            print(f"\n{'='*70}")
            print("Linux Hardening Tool - Main Menu")
            print(f"{'='*70}")
            print("\nTopics:")
            for tid, info in self.topics.items():
                print(f"  {tid}. {info['name']}")
            
            print("\nActions:")
            print("  scan   - Scan a topic")
            print("  fix    - Fix issues in a topic")
            print("  rollback - Rollback fixes for a topic")
            print("  status - Show hardening status")
            print("  report - Export comprehensive report")
            print("  all    - Scan all topics")
            print("  quit   - Exit")
            
            choice = input("\nEnter your choice: ").strip().lower()
            
            if choice == 'quit':
                print("\nExiting...")
                break
            elif choice == 'status':
                topic = input("Enter topic ID (or press Enter for all): ").strip()
                self.show_status(topic if topic else None)
            elif choice == 'report':
                self.export_report()
            elif choice == 'all':
                for tid in self.topics.keys():
                    self.run_script(tid, 'scan')
            elif choice in ['scan', 'fix', 'rollback']:
                topic = input("Enter topic ID: ").strip()
                if topic in self.topics:
                    if choice == 'rollback':
                        confirm = input(f"Rollback {self.topics[topic]['name']}? (yes/no): ")
                        if confirm.lower() == 'yes':
                            self.rollback_topic(topic)
                    else:
                        self.run_script(topic, choice)
                else:
                    print(f"[ERROR] Invalid topic ID: {topic}")
            else:
                print(f"[ERROR] Invalid choice: {choice}")

def main():
    if os.geteuid() != 0:
        print("[ERROR] This tool must be run as root!")
        sys.exit(1)
    
    controller = HardeningController()
    
    if len(sys.argv) > 1:
        # Command-line mode
        mode = sys.argv[1]
        if mode == 'scan-all':
            for tid in controller.topics.keys():
                controller.run_script(tid, 'scan')
        elif mode == 'report':
            controller.export_report()
        else:
            print(f"Usage: {sys.argv[0]} [scan-all|report]")
    else:
        # Interactive mode
        controller.display_menu()

if __name__ == "__main__":
    main()
