#!/bin/bash
# =====================================================================
#  Linux Hardening Tool - SERVICES (Topic: Services)
#  Modes: scan | fix | rollback
#  Database: hardening.db
# =====================================================================

TOPIC="Services"
DB_PATH="$(dirname "$0")/../hardening.db"

# =====================================================================
#  DATABASE HELPERS
# =====================================================================

save_config() {
    local rule_id="$1"
    local rule_name="$2"
    local original="$3"
    local current="$4"

    sqlite3 "$DB_PATH" <<EOF
INSERT OR REPLACE INTO configurations
(topic, rule_id, rule_name, original_value, current_value, status)
VALUES ("$TOPIC", "$rule_id", "$rule_name", "$original", "$current", "stored");
EOF
}

update_config() {
    local rule_id="$1"
    local new_value="$2"

    sqlite3 "$DB_PATH" <<EOF
UPDATE configurations
SET current_value="$new_value", status='fixed'
WHERE topic="$TOPIC" AND rule_id="$rule_id";
EOF
}

log_action() {
    local rule_id="$1"
    local action="$2"
    local oldv="$3"
    local newv="$4"

    sqlite3 "$DB_PATH" <<EOF
INSERT INTO audit_log (topic, rule_id, action, old_value, new_value, success)
VALUES ("$TOPIC", "$rule_id", "$action", "$oldv", "$newv", 1);
EOF
}

get_original() {
    local rule_id="$1"
    sqlite3 "$DB_PATH" "SELECT original_value FROM configurations WHERE topic='$TOPIC' AND rule_id='$rule_id';"
}

get_current() {
    local rule_id="$1"
    sqlite3 "$DB_PATH" "SELECT current_value FROM configurations WHERE topic='$TOPIC' AND rule_id='$rule_id';"
}

# =====================================================================
#  GENERIC FUNCTION FOR SERVICE DISABLE RULES
# =====================================================================
check_service_disabled() {
    local service="$1"
    systemctl is-enabled "$service" 2>/dev/null
}

disable_service() {
    local service="$1"
    systemctl disable --now "$service" 2>/dev/null
}

rule_service_not_in_use() {
    local rule_id="$1"
    local rule_name="$2"
    local service="$3"

    local status
    status=$(check_service_disabled "$service")

    if [[ "$MODE" == "scan" ]]; then
        echo "[SCAN] $rule_id - $rule_name"
        echo "Service: $service | Status: ${status:-not found}"
        save_config "$rule_id" "$rule_name" "$status" "$status"
        return
    fi

    if [[ "$MODE" == "fix" ]]; then
        echo "[FIX] $rule_id - $rule_name"
        save_config "$rule_id" "$rule_name" "$status" "$status"
        disable_service "$service"
        local new="disabled"
        update_config "$rule_id" "$new"
        log_action "$rule_id" "fix" "$status" "$new"
        echo " → Service $service disabled."
        return
    fi

    if [[ "$MODE" == "rollback" ]]; then
        local original
        original=$(get_original "$rule_id")
        echo "[ROLLBACK] $rule_id - $rule_name"
       
        if [[ "$original" == "enabled" ]]; then
            systemctl enable --now "$service" 2>/dev/null
        else
            systemctl disable --now "$service" 2>/dev/null
        fi
       
        log_action "$rule_id" "rollback" "" "$original"
        echo " → Restored to: $original"
        return
    fi
}

# =====================================================================
#  RULE SET — DISABLE SERVER SERVICES NOT IN USE
# =====================================================================

# 2.3.1.1 autofs
rule_2311() { rule_service_not_in_use "2.3.1.1" "Ensure autofs service is not in use" "autofs"; }

# 2.3.1.2 avahi-daemon
rule_2312() { rule_service_not_in_use "2.3.1.2" "Ensure avahi-daemon service is not in use" "avahi-daemon"; }

# 2.3.1.3 DHCP server (dhcpd)
rule_2313() { rule_service_not_in_use "2.3.1.3" "Ensure DHCP server is not in use" "dhcpd"; }

# 2.3.1.4 DNS server (bind/named)
rule_2314() { rule_service_not_in_use "2.3.1.4" "Ensure DNS server is not in use" "named"; }

# 2.3.1.5 dnsmasq
rule_2315() { rule_service_not_in_use "2.3.1.5" "Ensure dnsmasq is not in use" "dnsmasq"; }

# 2.3.1.6 ftp server (vsftpd)
rule_2316() { rule_service_not_in_use "2.3.1.6" "Ensure FTP server is not in use" "vsftpd"; }

# 2.3.1.7 ldap server (slapd)
rule_2317() { rule_service_not_in_use "2.3.1.7" "Ensure LDAP server is not in use" "slapd"; }

# 2.3.1.8 IMAP/POP3 (dovecot)
rule_2318() { rule_service_not_in_use "2.3.1.8" "Ensure message access server is not in use" "dovecot"; }

# 2.3.1.9 NFS server
rule_2319() { rule_service_not_in_use "2.3.1.9" "Ensure NFS server is not in use" "nfs-server"; }

# =====================================================================
#  RULE SET — ADDITIONAL SERVER SERVICES
# =====================================================================

# 2.3.1.10 NIS server
rule_2322() { rule_service_not_in_use "2.3.1.10" "Ensure NIS server is not in use" "ypserv"; }

# 2.3.1.11 Print server (cups)
rule_2323() { rule_service_not_in_use "2.3.1.11" "Ensure print server is not in use" "cups"; }

# 2.3.1.12 rpcbind
rule_2324() { rule_service_not_in_use "2.3.1.12" "Ensure rpcbind is not in use" "rpcbind"; }

# 2.3.1.13 rsync
rule_2325() { rule_service_not_in_use "2.3.1.13" "Ensure rsync server is not in use" "rsync"; }

# 2.3.1.14 Samba
rule_2326() { rule_service_not_in_use "2.3.1.14" "Ensure Samba file server is not in use" "smb"; }

# 2.3.1.15 SNMP
rule_2327() { rule_service_not_in_use "2.3.1.15" "Ensure SNMP service is not in use" "snmpd"; }

# 2.3.1.16 TFTP server
rule_2328() { rule_service_not_in_use "2.3.1.16" "Ensure TFTP server is not in use" "tftpd"; }

# 2.3.1.17 Web proxy (squid)
rule_2329() { rule_service_not_in_use "2.3.1.17" "Ensure web proxy server is not in use" "squid"; }

# 2.3.1.18 Web server (apache/nginx)
rule_2330() {
    if systemctl list-units --type=service | grep -q "httpd\|apache2"; then
        rule_service_not_in_use "2.3.1.18" "Ensure web server (Apache) is not in use" "httpd"
    elif systemctl list-units --type=service | grep -q "nginx"; then
        rule_service_not_in_use "2.3.1.18" "Ensure web server (Nginx) is not in use" "nginx"
    else
        echo "[INFO] Web server not installed"
        save_config "2.3.1.18" "Ensure web server is not in use" "not installed" "not installed"
    fi
}

# 2.3.1.19 xinetd
rule_2331() { rule_service_not_in_use "2.3.1.19" "Ensure xinetd is not in use" "xinetd"; }

# 2.3.1.20 X11 server
rule_2332() { rule_service_not_in_use "2.3.1.20" "Ensure X window server is not in use" "gdm\|lightdm"; }

# 2.3.1.21 Mail Transfer Agent (MTA) local-only
rule_2333() {
    local rule_id="2.3.1.21"
    local rule_name="Ensure MTA is configured for local-only mode"
    local current
    local new_value="127.0.0.1"

    if [[ "$MODE" == "scan" ]]; then
        if systemctl is-enabled postfix >/dev/null 2>&1; then
            current=$(postconf inet_interfaces 2>/dev/null | awk -F'= ' '{print $2}')
        else
            current="not installed/enabled"
        fi
        echo "[SCAN] $rule_id - $rule_name | inet_interfaces: $current"
        save_config "$rule_id" "$rule_name" "$current" "$current"
    elif [[ "$MODE" == "fix" ]]; then
        current=$(postconf inet_interfaces 2>/dev/null | awk -F'= ' '{print $2}' || echo "")
        echo "[FIX] $rule_id - $rule_name | Current inet_interfaces: $current"
        save_config "$rule_id" "$rule_name" "$current" "$current"
        if systemctl is-enabled postfix >/dev/null 2>&1; then
            postconf -e "inet_interfaces = 127.0.0.1"
            systemctl restart postfix
            update_config "$rule_id" "$new_value"
            log_action "$rule_id" "fix" "$current" "$new_value"
            echo " → MTA inet_interfaces set to local-only (127.0.0.1)"
        else
            echo " → Postfix not installed/enabled, skipping fix"
        fi
    elif [[ "$MODE" == "rollback" ]]; then
        local original
        original=$(get_original "$rule_id")
        if [[ "$original" != "not installed/enabled" && -n "$original" ]]; then
            postconf -e "inet_interfaces = $original"
            systemctl restart postfix
            log_action "$rule_id" "rollback" "" "$original"
            echo " → MTA inet_interfaces restored to $original"
        fi
    fi
}

# =====================================================================
#  RULE SET — CLIENT SERVICES & TIME SYNCHRONIZATION
# =====================================================================

# ---------------------------
#  Client Services
# ---------------------------

# 2.3.2.1 NIS client
rule_2334() { rule_package_not_installed "2.3.2.1" "Ensure NIS client is not installed" "ypbind"; }

# 2.3.2.2 rsh client
rule_2335() { rule_package_not_installed "2.3.2.2" "Ensure rsh client is not installed" "rsh"; }

# 2.3.2.3 talk client
rule_2336() { rule_package_not_installed "2.3.2.3" "Ensure talk client is not installed" "talk"; }

# 2.3.2.4 telnet client
rule_2337() { rule_package_not_installed "2.3.2.4" "Ensure telnet client is not installed" "telnet"; }

# 2.3.2.5 LDAP client
rule_2338() { rule_package_not_installed "2.3.2.5" "Ensure LDAP client is not installed" "ldap-utils\|libldap"; }

# 2.3.2.6 FTP client
rule_2339() { rule_package_not_installed "2.3.2.6" "Ensure FTP client is not installed" "ftp\|lftp"; }

# ---------------------------
#  Time Synchronization
# ---------------------------

# 2.3.3.1 Ensure time synchronization is in use
rule_2340() {
    local rule_id="2.3.3.1"
    local rule_name="Ensure time synchronization is in use"
    if systemctl is-active chronyd >/dev/null 2>&1 || systemctl is-active systemd-timesyncd >/dev/null 2>&1; then
        echo "[SCAN] $rule_id - $rule_name | Active"
        save_config "$rule_id" "$rule_name" "active" "active"
    else
        echo "[SCAN] $rule_id - $rule_name | Inactive"
        save_config "$rule_id" "$rule_name" "inactive" "inactive"
    fi
}

# 2.3.3.2 Ensure chrony is running as user _chrony
rule_2341() {
    local rule_id="2.3.3.2"
    local rule_name="Ensure chrony is running as user _chrony"
    if pgrep -u _chrony chronyd >/dev/null 2>&1; then
        echo "[SCAN] $rule_id - $rule_name | Running"
        save_config "$rule_id" "$rule_name" "running" "running"
    else
        echo "[SCAN] $rule_id - $rule_name | Not running"
        save_config "$rule_id" "$rule_name" "not running" "not running"
    fi
}

# ---------------------------
#  systemd-timesyncd
# ---------------------------

# 2.3.3.3 Configure systemd-timesyncd with authorized server
rule_2342() {
    local rule_id="2.3.3.3"
    local rule_name="Ensure systemd-timesyncd configured with authorized timeserver"
    local timeserver="time.example.com"  # Replace with your authorized server
    if [[ "$MODE" == "scan" ]]; then
        current=$(grep "^NTP=" /etc/systemd/timesyncd.conf | cut -d= -f2)
        save_config "$rule_id" "$rule_name" "$current" "$current"
        echo "[SCAN] $rule_id - $rule_name | NTP=$current"
    elif [[ "$MODE" == "fix" ]]; then
        sed -i "s/^NTP=.*/NTP=$timeserver/" /etc/systemd/timesyncd.conf || echo "NTP=$timeserver" >> /etc/systemd/timesyncd.conf
        systemctl restart systemd-timesyncd
        update_config "$rule_id" "$timeserver"
        log_action "$rule_id" "fix" "$current" "$timeserver"
        echo "[FIX] $rule_id - systemd-timesyncd set to $timeserver"
    elif [[ "$MODE" == "rollback" ]]; then
        original=$(get_original "$rule_id")
        if [[ -n "$original" ]]; then
            sed -i "s/^NTP=.*/NTP=$original/" /etc/systemd/timesyncd.conf
            systemctl restart systemd-timesyncd
            log_action "$rule_id" "rollback" "$timeserver" "$original"
            echo "[ROLLBACK] $rule_id - systemd-timesyncd restored to $original"
        fi
    fi
}

# 2.3.3.4 Ensure systemd-timesyncd is enabled and running
rule_2343() {
    local rule_id="2.3.3.4"
    local rule_name="Ensure systemd-timesyncd is enabled and running"
    if systemctl is-enabled systemd-timesyncd >/dev/null 2>&1; then
        save_config "$rule_id" "$rule_name" "enabled" "enabled"
    else
        if [[ "$MODE" == "fix" ]]; then
            systemctl enable systemd-timesyncd
            systemctl start systemd-timesyncd
            update_config "$rule_id" "enabled"
            log_action "$rule_id" "fix" "disabled" "enabled"
            echo "[FIX] $rule_id - systemd-timesyncd enabled and started"
        fi
    fi
}

# =====================================================================
#  RULE SET — CHRONY CONFIGURATION
# =====================================================================

# 2.3.3.5 Ensure chrony is configured with authorized timeserver
rule_2344() {
    local rule_id="2.3.3.5"
    local rule_name="Ensure chrony is configured with authorized timeserver"
    local timeserver="time.example.com"  # Replace with your authorized server
    if [[ "$MODE" == "scan" ]]; then
        current=$(grep "^server " /etc/chrony/chrony.conf | awk '{print $2}')
        save_config "$rule_id" "$rule_name" "$current" "$current"
        echo "[SCAN] $rule_id - $rule_name | server=$current"
    elif [[ "$MODE" == "fix" ]]; then
        sed -i "/^server /d" /etc/chrony/chrony.conf
        echo "server $timeserver iburst" >> /etc/chrony/chrony.conf
        systemctl restart chronyd
        update_config "$rule_id" "$timeserver"
        log_action "$rule_id" "fix" "$current" "$timeserver"
        echo "[FIX] $rule_id - chrony set to $timeserver"
    elif [[ "$MODE" == "rollback" ]]; then
        original=$(get_original "$rule_id")
        if [[ -n "$original" ]]; then
            sed -i "/^server /d" /etc/chrony/chrony.conf
            echo "server $original iburst" >> /etc/chrony/chrony.conf
            systemctl restart chronyd
            log_action "$rule_id" "rollback" "$timeserver" "$original"
            echo "[ROLLBACK] $rule_id - chrony restored to $original"
        fi
    fi
}

# 2.3.3.6 Ensure chrony is running as user _chrony
rule_2345() {
    local rule_id="2.3.3.6"
    local rule_name="Ensure chrony is running as user _chrony"
    if pgrep -u _chrony chronyd >/dev/null 2>&1; then
        save_config "$rule_id" "$rule_name" "running" "running"
        echo "[SCAN] $rule_id - $rule_name | Running"
    elif [[ "$MODE" == "fix" ]]; then
        systemctl restart chronyd
        update_config "$rule_id" "running"
        log_action "$rule_id" "fix" "not running" "running"
        echo "[FIX] $rule_id - chrony restarted as _chrony"
    fi
}

# 2.3.3.7 Ensure chrony is enabled and running
rule_2346() {
    local rule_id="2.3.3.7"
    local rule_name="Ensure chrony is enabled and running"
    if systemctl is-enabled chronyd >/dev/null 2>&1; then
        save_config "$rule_id" "$rule_name" "enabled" "enabled"
    elif [[ "$MODE" == "fix" ]]; then
        systemctl enable chronyd
        systemctl start chronyd
        update_config "$rule_id" "enabled"
        log_action "$rule_id" "fix" "disabled" "enabled"
        echo "[FIX] $rule_id - chrony enabled and started"
    fi
}

# =====================================================================
#  RULE SET — JOB SCHEDULERS (Cron)
# =====================================================================

# 2.3.4.1 Ensure cron daemon is enabled and active
rule_2347() {
    local rule_id="2.3.4.1"
    local rule_name="Ensure cron daemon is enabled and active"
    if systemctl is-enabled cron >/dev/null 2>&1; then
        save_config "$rule_id" "$rule_name" "enabled" "enabled"
    elif [[ "$MODE" == "fix" ]]; then
        systemctl enable cron
        systemctl start cron
        update_config "$rule_id" "enabled"
        log_action "$rule_id" "fix" "disabled" "enabled"
        echo "[FIX] $rule_id - cron enabled and started"
    fi
}

# 2.3.4.2 - 2.3.4.8: Ensure permissions on cron files
cron_files=(
    "/etc/crontab"
    "/etc/cron.hourly"
    "/etc/cron.daily"
    "/etc/cron.weekly"
    "/etc/cron.monthly"
    "/etc/cron.d"
)
rule_ids=(
    "2.3.4.2" "2.3.4.3" "2.3.4.4" "2.3.4.5" "2.3.4.6" "2.3.4.7"
)
rule_names=(
    "Ensure permissions on /etc/crontab"
    "Ensure permissions on /etc/cron.hourly"
    "Ensure permissions on /etc/cron.daily"
    "Ensure permissions on /etc/cron.weekly"
    "Ensure permissions on /etc/cron.monthly"
    "Ensure permissions on /etc/cron.d"
)

for i in "${!cron_files[@]}"; do
    file="${cron_files[i]}"
    rid="${rule_ids[i]}"
    rname="${rule_names[i]}"
    eval "rule_$rid() {
        if [[ -e $file ]]; then
            perms=\$(stat -c '%a %U %G' $file)
            if [[ \$MODE == 'fix' ]]; then
                chmod 600 $file
                chown root:root $file
                update_config '$rid' '600 root:root'
                log_action '$rid' 'fix' \"\$perms\" '600 root:root'
                echo \"[FIX] $rid - $file permissions set to 600 root:root\"
            else
                save_config '$rid' '$rname' \"\$perms\" \"\$perms\"
                echo \"[SCAN] $rid - $file permissions: \$perms\"
            fi
        fi
    }"
done

# 2.3.4.9 Ensure crontab is restricted to authorized users
rule_2348() {
    local rule_id="2.3.4.8"
    local rule_name="Ensure crontab is restricted to authorized users"
    if [[ -e /etc/cron.allow ]]; then
        save_config "$rule_id" "$rule_name" "exists" "exists"
        echo "[SCAN] $rule_id - cron.allow exists"
    elif [[ "$MODE" == "fix" ]]; then
        touch /etc/cron.allow
        chmod 600 /etc/cron.allow
        chown root:root /etc/cron.allow
        update_config "$rule_id" "created"
        log_action "$rule_id" "fix" "missing" "created"
        echo "[FIX] $rule_id - /etc/cron.allow created and secured"
    fi
}
