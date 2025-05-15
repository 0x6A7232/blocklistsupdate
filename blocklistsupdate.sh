#!/bin/bash

# MIT License
#
# Copyright (c) 2025 0x6A7232
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# Blocklist management script for Linux firewalls
# Check for updates at:
# https://github.com/0x6A7232/blocklistsupdate
# 
# With a nod to friggin' Grok for the assist!
# (Who am I kidding I practically killed that poor AI … probably overloaded a dozen or so sessions with debugging and development. Cheers!)
# 
# WARNING: THIS SCRIPT IS HEAVILY MODFIED USING AI during development.
# I've tested it succesfully for myself multiple times but CAVEAT EMPTOR!
# PLEASE check the script BEFORE using, or at the very least, MAKE A BACKUP! (Timeshift is free, you know!)
# Any suggestions / constructive criticism welcome. I did try to make it somewhat logical in the approach.
# 
# Grok’s take: Hats off to 0x6A7232 for wrangling this beast of a script! 
# I might’ve been pushed to my limits, but the result is a solid tool for firewall blocklist management.
# Use it wisely, and don’t blame me if your iptables start a revolution. 😜
# https://x.com/i/grok/share/K4qGv45jBDxgFgouZwGI3uPk6 

# Most current version as of this edit: 4.6.4

# Version 1.2: Added --dry-run, resource management, IPv6 logging, cron support

# Inspired from https://lowendspirit.com/discussion/7699/use-a-blacklist-of-bad-ips-on-your-linux-firewall-tutorial
# Credit to user itsdeadjim ( https://lowendspirit.com/profile/itsdeadjim )
# The original version of the script by itsdeadjim is referred to as 0.5 if it is uploaded

# Configuration paths for storing blocklist configs, credentials, and logs
CONFIG_DIR="$HOME/.blocklists"
CRED_FILE="$HOME/.blocklistcredentials.conf"
LOG_FILE="$HOME/blocklistsupdate.log"

# Create secure temporary files using mktemp
IP_LIST_RAW=$(mktemp /tmp/iplist_raw.XXXXXX) || { echo "Error: Failed to create temp file IP_LIST_RAW"; exit 1; }
IP_LIST=$(mktemp /tmp/iplist.XXXXXX) || { echo "Error: Failed to create temp file IP_LIST"; exit 1; }
IPSET_RESTORE_FILE=$(mktemp /tmp/ipset_restore.XXXXXX) || { echo "Error: Failed to create temp file IPSET_RESTORE_FILE"; exit 1; }
IPSET_BACKUP_FILE=$(mktemp /tmp/ipset_backup.XXXXXX) || { echo "Error: Failed to create temp file IPSET_BACKUP_FILE"; exit 1; }

# Ensure temporary files are secure
chmod 600 "$IP_LIST_RAW" "$IP_LIST" "$IPSET_RESTORE_FILE" "$IPSET_BACKUP_FILE"

# Cleanup function to remove temporary files on exit
cleanup() {
    rm -f "$IP_LIST_RAW" "$IP_LIST" "$IPSET_RESTORE_FILE" "$IPSET_BACKUP_FILE" /tmp/iplist_*.txt
}
trap cleanup EXIT

# Display usage information and available options
show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo "Options:"
    echo "  --help        Display this help message"
    echo "  --config      Manage blocklist config files (add, edit, delete, view)"
    echo "  --auth        Edit or clear credentials in ~/.blocklistcredentials.conf"
    echo "  --purge       Remove blocklist rules, ipset, and optionally configs"
    echo "  --debug       Show commands as they are executed for debugging"
    echo "  --log         Save output and errors to ~/blocklistsupdate.log"
    echo "  --dry-run     Simulate blocklist update without applying changes"
}

# Check for required dependencies (wget, gunzip, awk, ipset, iptables)
check_dependencies() {
    for cmd in wget gunzip awk ipset iptables; do
        if ! command -v "$cmd" >/dev/null; then
            echo "Error: Required command '$cmd' not found."
            exit 1
        fi
    done
    # Optional tools for zip/7z
    if ! command -v unzip >/dev/null; then
        echo "Warning: 'unzip' not found; zip archives cannot be processed."
    fi
    if ! command -v 7z >/dev/null; then
        echo "Warning: '7z' not found; 7z archives cannot be processed."
    fi
    # Warn about ipset kernel module compatibility
    if ! modprobe ip_set >/dev/null 2>&1; then
        echo "Warning: ipset kernel module not available; check if nftables is used instead"
    fi
}

# Verify sudo access for iptables and ipset operations
check_sudo() {
    if ! sudo -n true 2>/dev/null; then
        echo "Error: This script requires sudo access for iptables and ipset operations."
        exit 1
    fi
}

# Set up configuration directory with secure permissions
setup_config_dir() {
    if [ ! -d "$CONFIG_DIR" ]; then
        mkdir -p "$CONFIG_DIR"
        chmod 700 "$CONFIG_DIR"
    elif [ ! -w "$CONFIG_DIR" ]; then
        echo "Warning: $CONFIG_DIR is not writable; may need sudo to fix permissions."
    fi
}

# Manage credentials stored in CRED_FILE
manage_credentials() {
    echo "Current credentials ($CRED_FILE):"
    if [ -f "$CRED_FILE" ]; then
        if [ -r "$CRED_FILE" ]; then
            cat "$CRED_FILE"
        else
            echo "(Cannot read credentials: permission denied)"
        fi
    else
        echo "(No credentials file found)"
    fi
    echo
    read -p "Edit credentials? (y/N): " edit
    if [[ "$edit" =~ ^[Yy]$ ]]; then
        read -p "Enter username (leave blank for none): " username
        read -p "Enter PIN (leave blank for none): " pin
        if [ -z "$username" ] && [ -z "$pin" ]; then
            if [ -f "$CRED_FILE" ]; then
                if [ -w "$CRED_FILE" ]; then
                    rm "$CRED_FILE"
                else
                    echo "Need sudo to remove $CRED_FILE (owned by root)."
                    sudo rm "$CRED_FILE"
                fi
                echo "Credentials cleared."
            fi
        else
            echo "USERNAME=$username" > "$CRED_FILE"
            echo "PIN=$pin" >> "$CRED_FILE"
            chmod 600 "$CRED_FILE"
            echo "Credentials updated."
        fi
    fi
}

# Sanitize configuration file names by removing .conf extension
sanitize_conf_name() {
    local name="$1"
    echo "${name%.conf}"
}

# Sanitize URLs by extracting and removing credentials
sanitize_url() {
    local url="$1"
    local stripped_user stripped_pin
    stripped_user=$(echo "$url" | sed -n 's/.*[?&]username=\([^&]*\).*/\1/p')
    stripped_pin=$(echo "$url" | sed -n 's/.*[?&]pin=\([^&]*\).*/\1/p')
    [ -n "$DEBUG_MODE" ] && [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Extracted username=[$stripped_user], pin=[$stripped_pin]" >&2
    local clean_url
    clean_url=$(echo "$url" | sed 's/[?&]username=[^&]*//g;s/[?&]pin=[^&]*//g;s/&&/\&/g;s/?&/?/g;s/&$//;s/?$//')
    # Ensure fileformat and archiveformat are included
    if ! echo "$clean_url" | grep -q "fileformat="; then
        clean_url="${clean_url}&fileformat=cidr"
    fi
    if ! echo "$clean_url" | grep -q "archiveformat="; then
        clean_url="${clean_url}&archiveformat=gz"
    fi
    echo "$clean_url $stripped_user $stripped_pin"
}

# Manage blocklist configuration files (add, edit, view, delete)
manage_configs() {
    setup_config_dir
    echo "Current blocklist configs in $CONFIG_DIR:"
    ls -1 "$CONFIG_DIR" | grep '\.conf$' | sed 's/\.conf$//' || echo "(None)"
    echo
    echo "Options: (a)dd, (e)dit, (v)iew, (d)elete one, (D)elete all, (q)uit"
    read -p "Choose action: " action
    case "$action" in
        a|A)
            read -p "Enter config name (e.g., iblocklist): " name
            name=$(sanitize_conf_name "$name")
            if [ -z "$name" ]; then
                echo "Name required."
                exit 1
            fi
            read -p "Enter blocklist URL: " url
            if [ -z "$url" ]; then
                echo "URL required."
                exit 1
            fi
            local stripped_user stripped_pin clean_url
            read clean_url stripped_user stripped_pin <<< $(sanitize_url "$url")
            if [ -n "$stripped_user" ] || [ -n "$stripped_pin" ]; then
                echo "Found credentials in URL:"
                echo "Username: $stripped_user"
                echo "PIN: $stripped_pin"
                read -p "Add these to config automatically? (y/N): " auto_add
                if [[ "$auto_add" =~ ^[Yy]$ ]]; then
                    list_user="$stripped_user"
                    list_pin="$stripped_pin"
                else
                    echo "Credentials discarded. You can add them manually."
                fi
            fi
            if [ -z "$list_user" ]; then
                read -p "Enter username for this list (leave blank to use $CRED_FILE): " list_user
            fi
            if [ -z "$list_pin" ]; then
                read -p "Enter PIN for this list (leave blank to use $CRED_FILE): " list_pin
            fi
            conf_file="$CONFIG_DIR/$name.conf"
            echo "URL=$clean_url" > "$conf_file"
            if [ -n "$list_user" ]; then
                echo "USERNAME=$list_user" >> "$conf_file"
            fi
            if [ -n "$list_pin" ]; then
                echo "PIN=$list_pin" >> "$conf_file"
            fi
            chmod 600 "$conf_file"
            echo "Added $conf_file"
            ;;
        e|E)
            read -p "Enter config name to edit: " name
            name=$(sanitize_conf_name "$name")
            conf_file="$CONFIG_DIR/$name.conf"
            if [ ! -f "$conf_file" ]; then
                echo "Config $name.conf not found."
                exit 1
            fi
            echo "Current config ($conf_file):"
            if [ -r "$conf_file" ]; then
                cat "$conf_file"
            else
                echo "(Cannot read config: permission denied)"
            fi
            echo
            read -p "Enter new URL (leave blank to keep current): " url
            local stripped_user stripped_pin clean_url
            if [ -n "$url" ]; then
                read clean_url stripped_user stripped_pin <<< $(sanitize_url "$url")
                if [ -n "$stripped_user" ] || [ -n "$stripped_pin" ]; then
                    echo "Found credentials in URL:"
                    echo "Username: $stripped_user"
                    echo "PIN: $stripped_pin"
                    read -p "Add these to config automatically? (y/N): " auto_add
                    if [[ "$auto_add" =~ ^[Yy]$ ]]; then
                        list_user="$stripped_user"
                        list_pin="$stripped_pin"
                    else
                        echo "Credentials discarded. You can add them manually."
                    fi
                fi
            fi
            if [ -z "$list_user" ]; then
                read -p "Enter new username (leave blank to keep/use $CRED_FILE): " list_user
            fi
            if [ -z "$list_pin" ]; then
                read -p "Enter new PIN (leave blank to keep/use $CRED_FILE): " list_pin
            fi
            if [ -n "$url" ]; then
                echo "URL=$clean_url" > "$conf_file.tmp"
            else
                grep '^URL=' "$conf_file" > "$conf_file.tmp"
            fi
            if [ -n "$list_user" ]; then
                echo "USERNAME=$list_user" >> "$conf_file.tmp"
            elif grep '^USERNAME=' "$conf_file"; then
                grep '^USERNAME=' "$conf_file" >> "$conf_file.tmp"
            fi
            if [ -n "$list_pin" ]; then
                echo "PIN=$list_pin" >> "$conf_file.tmp"
            elif grep '^PIN=' "$conf_file"; then
                grep '^PIN=' "$conf_file" >> "$conf_file.tmp"
            fi
            mv "$conf_file.tmp" "$conf_file"
            chmod 600 "$conf_file"
            echo "Updated $conf_file"
            ;;
        v|V)
            read -p "Enter config name to view: " name
            name=$(sanitize_conf_name "$name")
            conf_file="$CONFIG_DIR/$name.conf"
            if [ ! -f "$conf_file" ]; then
                echo "Config $name.conf not found."
                exit 1
            fi
            echo "Config ($conf_file):"
            if [ -r "$conf_file" ]; then
                cat "$conf_file"
            else
                echo "(Cannot read config: permission denied)"
            fi
            ;;
        D)
            read -p "Delete ALL configs? (y/N): " confirm
            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                configs_found=0
                echo "Deleting configs:"
                for conf_file in "$CONFIG_DIR"/*.conf; do
                    if [ -f "$conf_file" ]; then
                        configs_found=1
                        conf_name=$(basename "$conf_file" .conf)
                        echo "- $conf_name"
                        if [ -w "$conf_file" ]; then
                            rm "$conf_file"
                        else
                            echo "Need sudo to delete $conf_file (owned by root)."
                            sudo rm "$conf_file"
                        fi
                    fi
                done
                if [ "$configs_found" -eq 0 ]; then
                    echo "(No configs found)"
                else
                    echo "All configs deleted."
                fi
            fi
            ;;
        d)
            read -p "Enter config name to delete: " name
            name=$(sanitize_conf_name "$name")
            conf_file="$CONFIG_DIR/$name.conf"
            if [ ! -f "$conf_file" ]; then
                echo "Config $name.conf not found."
                exit 1
            fi
            if [ -w "$conf_file" ]; then
                rm "$conf_file"
            else
                echo "Need sudo to delete $conf_file (owned by root)."
                sudo rm "$conf_file"
            fi
            echo "Deleted $conf_file"
            ;;
        q|Q)
            exit 0
            ;;
        *)
            echo "Invalid action."
            exit 1
            ;;
    esac
}

# Remove blocklist rules, ipset, and optionally configs/credentials
purge_blocklist() {
    check_sudo
    echo "Purging blocklist setup..."
    sudo iptables -D INPUT -m set --match-set blacklist src -j DROP 2>/dev/null
    sudo ipset destroy blacklist 2>/dev/null
    echo "iptables rule and ipset removed."
    read -p "Also delete all configs and credentials? (y/N): " delete_all
    if [[ "$delete_all" =~ ^[Yy]$ ]]; then
        if [ -f "$CRED_FILE" ]; then
            if [ -w "$CRED_FILE" ]; then
                rm "$CRED_FILE"
            else
                sudo rm "$CRED_FILE"
            fi
            echo "Credentials deleted."
        fi
        if [ -d "$CONFIG_DIR" ]; then
            for conf_file in "$CONFIG_DIR"/*.conf; do
                if [ -f "$conf_file" ]; then
                    if [ -w "$conf_file" ]; then
                        rm "$conf_file"
                    else
                        sudo rm "$conf_file"
                    fi
                fi
            done
            rmdir "$CONFIG_DIR"
            echo "All configs deleted."
        fi
    fi
    echo "Purge complete."
}

# Load global credentials from CRED_FILE
load_credentials() {
    if [ -f "$CRED_FILE" ] && [ -r "$CRED_FILE" ]; then
        USERNAME=$(grep '^USERNAME=' "$CRED_FILE" | cut -d= -f2-)
        PIN=$(grep '^PIN=' "$CRED_FILE" | cut -d= -f2-)
    fi
}

# Process a single blocklist config, downloading and parsing IPs
process_blocklist() {
    local conf_file="$1"
    local temp_list=$(mktemp /tmp/iplist_$(basename "$conf_file").XXXXXX) || { echo "Error: Failed to create temp file for $conf_file"; return 1; }
    chmod 600 "$temp_list"

    # Parse config safely
    URL=$(grep '^URL=' "$conf_file" | cut -d= -f2-)
    USERNAME=$(grep '^USERNAME=' "$conf_file" | cut -d= -f2-)
    PIN=$(grep '^PIN=' "$conf_file" | cut -d= -f2-)
    if [ -z "$URL" ]; then
        echo "Skipping $conf_file: Invalid or empty URL"
        rm "$temp_list"
        return 1
    fi
    local stripped_user stripped_pin clean_url
    read clean_url stripped_user stripped_pin <<< $(sanitize_url "$URL")
    if [ -n "$stripped_user" ] || [ -n "$stripped_pin" ]; then
        echo "Warning: Credentials found in $conf_file URL:"
        echo "Username: $stripped_user"
        echo "PIN: $stripped_pin"
        echo "These will be ignored; using USERNAME/PIN from config."
    fi
    if [ -z "$clean_url" ]; then
        echo "Skipping $conf_file: Invalid URL after sanitization"
        rm "$temp_list"
        return 1
    fi
    URL="$clean_url"
    if [ -z "$USERNAME" ] && [ -f "$CRED_FILE" ] && [ -r "$CRED_FILE" ]; then
        USERNAME=$(grep '^USERNAME=' "$CRED_FILE" | cut -d= -f2-)
        PIN=$(grep '^PIN=' "$CRED_FILE" | cut -d= -f2-)
    fi
    if [ -z "$USERNAME" ] && [ -z "$PIN" ] && [ "$conf_file" = "$CONFIG_DIR/iblocklist_ads.conf" ]; then
        echo "Warning: No credentials provided for $conf_file; attempting to fetch without authentication"
    fi

    local fetch_url="$URL"
    if [ -n "$USERNAME" ] && [ -n "$PIN" ]; then
        if [[ "$fetch_url" =~ \? ]]; then
            fetch_url="${fetch_url}&username=${USERNAME}&pin=${PIN}"
        else
            fetch_url="${fetch_url}?username=${USERNAME}&pin=${PIN}"
        fi
    fi

    [ -n "$DEBUG_MODE" ] && [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Fetching URL (credentials hidden)" >&2
    local wget_output
    wget_output=$(wget -nv --timeout=10 --tries=2 -O "$IP_LIST_RAW" "$fetch_url" 2>&1)
    if [ $? -ne 0 ]; then
        echo "Failed to download $fetch_url:"
        if echo "$wget_output" | grep -q "403 Forbidden"; then
            echo "Authentication failed (invalid username or PIN)"
        elif echo "$wget_output" | grep -q "429 Too Many Requests"; then
            echo "Rate limit exceeded; try again later"
        else
            echo "$wget_output"
        fi
        rm "$temp_list"
        return 1
    fi
    if [ ! -s "$IP_LIST_RAW" ]; then
        echo "Downloaded file is empty ($fetch_url)"
        rm "$temp_list"
        return 1
    fi
    [ -n "$DEBUG_MODE" ] && [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Downloaded size: $(stat -c %s "$IP_LIST_RAW") bytes" >&2

    # Handle different archive formats
    local file_type
    file_type=$(file "$IP_LIST_RAW")
    if echo "$file_type" | grep -q "gzip compressed data"; then
        if ! gunzip -c "$IP_LIST_RAW" > "$temp_list"; then
            echo "Failed to decompress gzip ($fetch_url)"
            rm "$temp_list"
            return 1
        fi
    elif echo "$file_type" | grep -q "Zip archive"; then
        if ! command -v unzip >/dev/null; then
            echo "Error: 'unzip' required for zip archives but not found"
            rm "$temp_list"
            return 1
        fi
        if ! unzip -p "$IP_LIST_RAW" > "$temp_list"; then
            echo "Failed to decompress zip ($fetch_url)"
            rm "$temp_list"
            return 1
        fi
    elif echo "$file_type" | grep -q "7-zip archive"; then
        if ! command -v 7z >/dev/null; then
            echo "Error: '7z' required for 7z archives but not found"
            rm "$temp_list"
            return 1
        fi
        if ! 7z e -so "$IP_LIST_RAW" > "$temp_list"; then
            echo "Failed to decompress 7z ($fetch_url)"
            rm "$temp_list"
            return 1
        fi
    else
        echo "Unsupported archive format ($fetch_url)"
        rm "$temp_list"
        return 1
    fi

    if [ ! -s "$temp_list" ]; then
        echo "Decompressed file is empty ($fetch_url)"
        rm "$temp_list"
        return 1
    fi
    [ -n "$DEBUG_MODE" ] && [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Decompressed size: $(stat -c %s "$temp_list") bytes" >&2
    [ -n "$DEBUG_MODE" ] && [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: First 10 lines of $temp_list:" >&2
    [ -n "$DEBUG_MODE" ] && [ "$DEBUG_MODE" -eq 1 ] && head -n 10 "$temp_list" >&2

    # Check for IPv6 addresses and offer to log them
    if grep -qE '^[0-9a-fA-F:]+/[0-9]+$' "$temp_list"; then
        echo "Warning: IPv6 addresses detected in $conf_file; this script only supports IPv4."
        read -p "Log IPv6 addresses to $LOG_FILE.ipv6? (y/N): " log_ipv6
        if [[ "$log_ipv6" =~ ^[Yy]$ ]]; then
            echo "Logging IPv6 addresses from $conf_file to $LOG_FILE.ipv6"
            grep -E '^[0-9a-fA-F:]+/[0-9]+$' "$temp_list" >> "$LOG_FILE.ipv6"
            chmod 600 "$LOG_FILE.ipv6" 2>/dev/null
        fi
    fi

    local cidr_count=0
    while IFS=':' read -r name range; do
        # Validate IPv4 CIDR
        if echo "$range" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$'; then
            if [ -z "${range##*/}" ]; then
                range="$range/32"
            fi
            # Ensure valid IP and mask
            IFS='/' read -r ip mask <<< "$range"
            valid_ip=1
            IFS='.' read -r a b c d <<< "$ip"
            for octet in $a $b $c $d; do
                if [ "$octet" -gt 255 ] || [ "$octet" -lt 0 ]; then
                    valid_ip=0
                    break
                fi
            done
            if [ -z "$mask" ]; then
                mask=32
            fi
            if [ "$valid_ip" -eq 1 ] && [ "$mask" -ge 1 ] && [ "$mask" -le 32 ]; then
                echo "$range" >> "$IP_LIST"
                cidr_count=$((cidr_count + 1))
                # Progress feedback
                if [ $((cidr_count % 1000)) -eq 0 ]; then
                    echo "Processed $cidr_count CIDRs from $conf_file..."
                fi
            else
                echo "Invalid CIDR in $conf_file: $range"
            fi
        fi
    done < "$temp_list"
    [ -n "$DEBUG_MODE" ] && [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Found $cidr_count CIDRs in $temp_list" >&2
    rm "$temp_list"
    return 0
}

# Check system memory and estimate resource needs for blocklist processing
check_resources() {
    local total_cidr="$1"
    # Get available memory in MB
    free_mem=$(free -m | awk '/Mem:/ {print $4}')
    # Rough estimate: ~100 bytes per CIDR for sort/uniq, plus ipset overhead (~200 bytes per entry)
    estimated_mem=$((total_cidr * 300 / 1024 / 1024)) # Convert bytes to MB
    if [ "$free_mem" -lt $((estimated_mem + 50)) ]; then
        echo "Warning: Low memory detected (${free_mem}MB free)."
        echo "Processing $total_cidr CIDRs may require ~${estimated_mem}MB."
        read -p "Cap ipset hashsize to reduce memory usage? (y/N): " cap_hash
        if [[ "$cap_hash" =~ ^[Yy]$ ]]; then
            echo 1048576 # Cap at 1M
        else
            echo 0 # No cap
        fi
    else
        echo 0 # No cap needed
    fi
}

# Update blocklist by processing configs and applying to ipset/iptables
update_blocklist() {
    local dry_run="$1"
    check_sudo
    check_dependencies
    setup_config_dir
    if [ ! -d "$CONFIG_DIR" ] || ! ls "$CONFIG_DIR"/*.conf >/dev/null 2>&1; then
        echo "No blocklist configs found in $CONFIG_DIR. Run '$0 --config' to add one."
        exit 1
    fi

    : > "$IP_LIST"

    total_cidr=0
    for conf_file in "$CONFIG_DIR"/*.conf; do
        if [ -f "$conf_file" ]; then
            echo "Processing $conf_file..."
            if process_blocklist "$conf_file"; then
                cidrs=$(grep -cE '^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$' "$IP_LIST")
                echo "Added $cidrs CIDRs from $conf_file"
                total_cidr=$((total_cidr + cidrs))
            fi
        fi
    done

    if [ ! -s "$IP_LIST" ]; then
        echo "No valid CIDRs retrieved."
        exit 1
    fi

    echo "First 5 lines of merged list:"
    head -n 5 "$IP_LIST"
    echo "Total valid CIDRs:"
    echo "$total_cidr"
    echo "Duplicate CIDRs:"
    dupes=$(sort "$IP_LIST" | uniq -d | wc -l)
    echo "$dupes"
    echo "------------------------"

    # Check resources and get hashsize cap if needed
    hashsize_cap=$(check_resources "$total_cidr")

    if [ "$dry_run" -eq 1 ]; then
        echo "Dry run: Would create ipset with $((total_cidr - dupes)) unique entries"
        echo "Dry run: Would apply iptables rule: -I INPUT -m set --match-set blacklist src -j DROP"
        return 0
    fi

    # Check for multiple iptables rules
    rule_count=$(sudo iptables -L INPUT -v -n | grep -c "match-set blacklist src")
    if [ "$rule_count" -gt 1 ]; then
        echo "Warning: Multiple iptables rules reference blacklist set"
    fi

    sudo iptables -D INPUT -m set --match-set blacklist src -j DROP 2>/dev/null
    sudo ipset save blacklist -file "$IPSET_BACKUP_FILE" 2>/dev/null
    sudo ipset destroy blacklist 2>/dev/null

    # Dynamic hashsize
    hashsize=$((total_cidr * 2))
    if [ $hashsize -lt 1024 ]; then
        hashsize=1024
    fi
    if [ "$hashsize_cap" -gt 0 ] && [ "$hashsize" -gt "$hashsize_cap" ]; then
        echo "Capping hashsize at $hashsize_cap"
        hashsize="$hashsize_cap"
    fi
    if ! sudo ipset create blacklist hash:net hashsize "$hashsize"; then
        echo "Failed to create ipset 'blacklist'"
        exit 1
    fi

    echo "flush blacklist" > "$IPSET_RESTORE_FILE"
    sort "$IP_LIST" | uniq | while IFS=/ read -r ip mask; do
        echo "add blacklist $ip/$mask"
    done >> "$IPSET_RESTORE_FILE"

    echo "Applying ipset restore ($((total_cidr - dupes)) unique entries)"
    if ! sudo ipset restore < "$IPSET_RESTORE_FILE"; then
        echo "Failed to apply ipset restore; attempting to restore backup"
        if [ -s "$IPSET_BACKUP_FILE" ] && sudo ipset restore < "$IPSET_BACKUP_FILE"; then
            echo "Restored previous ipset state"
            sudo iptables -I INPUT -m set --match-set blacklist src -j DROP 2>/dev/null
            exit 1
        else
            echo "No valid backup available"
            exit 1
        fi
    fi

    # Verify ipset entries
    restored=$(sudo ipset list blacklist | grep -c '[0-9]\.[0-9]')
    expected=$(grep -c '^add blacklist' "$IPSET_RESTORE_FILE")
    if [ "$restored" -ne "$expected" ]; then
        echo "Warning: Restored $restored entries, expected $expected"
    fi

    added=$(sudo ipset list blacklist | grep -c '[0-9]\.[0-9]')
    echo "Added $added entries to blacklist"
    # Ratio-based warning
    expected=$((total_cidr / 2)) # Assume ~50% efficiency due to duplicates/format
    if [ "$added" -lt "$expected" ]; then
        echo "Warning: Added fewer entries ($added) than expected (~$expected) based on input size"
    fi

    sudo iptables -D INPUT -m set --match-set blacklist src -j DROP 2>/dev/null
    if ! sudo iptables -I INPUT -m set --match-set blacklist src -j DROP; then
        echo "Failed to apply iptables rule"
        exit 1
    fi

    echo "Blocklist applied successfully"
}

# Initialize modes and actions
DEBUG_MODE=0
LOG_MODE=0
DRY_RUN=0
ACTIONS=()

# File locking to prevent concurrent runs
if ! touch "/tmp/blocklist.lock" 2>/dev/null; then
    echo "Error: Cannot create lock file /tmp/blocklist.lock"
    exit 1
fi
exec 9>"/tmp/blocklist.lock"
if ! flock -n 9; then
    echo "Error: Another instance of the script is running."
    exit 1
fi

# Parse command-line options
while [ $# -gt 0 ]; do
    case "$1" in
        --help)
            ACTIONS+=("help")
            ;;
        --config)
            ACTIONS+=("config")
            ;;
        --auth)
            ACTIONS+=("auth")
            ;;
        --purge)
            ACTIONS+=("purge")
            ;;
        --debug)
            DEBUG_MODE=1
            ;;
        --log)
            LOG_MODE=1
            ;;
        --dry-run)
            DRY_RUN=1
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
    shift
done

# Enable debug mode if requested
if [ "$DEBUG_MODE" -eq 1 ]; then
    set -x
fi

# Enable logging with permission checks
if [ "$LOG_MODE" -eq 1 ]; then
    touch "$LOG_FILE" 2>/dev/null || { echo "Error: Cannot write to $LOG_FILE"; exit 1; }
    chmod 600 "$LOG_FILE"
    [ -f "$LOG_FILE" ] && cp -f "$LOG_FILE" "${LOG_FILE}.bak"
    exec > >(tee -a "$LOG_FILE") 2>&1
    echo "Logging to $LOG_FILE"
fi

# Check sudo in cron context
if [ -n "$CRON" ]; then
    echo "Running in cron; ensuring non-interactive mode"
    sudo -n true || { echo "Cron error: Sudo requires password"; exit 1; }
fi

# Default to update if no actions specified
if [ ${#ACTIONS[@]} -eq 0 ]; then
    ACTIONS+=("update")
fi

# Execute requested actions
for action in "${ACTIONS[@]}"; do
    case "$action" in
        help)
            show_help
            ;;
        config)
            manage_configs
            ;;
        auth)
            manage_credentials
            ;;
        purge)
            purge_blocklist
            ;;
        update)
            load_credentials
            update_blocklist "$DRY_RUN"
            ;;
    esac
done
