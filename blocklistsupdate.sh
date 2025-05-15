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

# Version 1.0: Added multiple blocklist support, config/credential management, --purge option, enhanced CLI

# Inspired from https://lowendspirit.com/discussion/7699/use-a-blacklist-of-bad-ips-on-your-linux-firewall-tutorial
# Credit to user itsdeadjim ( https://lowendspirit.com/profile/itsdeadjim )
# The original version of the script by itsdeadjim is referred to as 0.5 if it is uploaded

CONFIG_DIR="$HOME/.blocklists"
CRED_FILE="$HOME/.blocklistcredentials.conf"
LOG_FILE="$HOME/blocklistsupdate.log"

IP_LIST_RAW="/tmp/iplist.gz"
IP_LIST="/tmp/iplist.txt"
IPSET_RESTORE_FILE="/tmp/ipset_restore.txt"

trap 'rm -f "$IP_LIST_RAW" "$IP_LIST" "$IPSET_RESTORE_FILE"' EXIT

show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo "Options:"
    echo "  --help        Display this help message"
    echo "  --config      Manage blocklist config files (add, edit, delete, view)"
    echo "  --auth        Edit or clear credentials in ~/.blocklistcredentials.conf"
    echo "  --purge       Remove blocklist rules, ipset, and optionally configs"
    echo "  --debug       Show commands as they are executed for debugging"
    echo "  --log         Save output and errors to ~/blocklistsupdate.log"
}

setup_config_dir() {
    if [ ! -d "$CONFIG_DIR" ]; then
        mkdir -p "$CONFIG_DIR"
        chmod 700 "$CONFIG_DIR"
    elif [ ! -w "$CONFIG_DIR" ]; then
        echo "Warning: $CONFIG_DIR is not writable; may need sudo to fix permissions."
    fi
}

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

sanitize_conf_name() {
    local name="$1"
    echo "${name%.conf}"
}

sanitize_url() {
    local url="$1"
    local stripped_user stripped_pin
    stripped_user=$(echo "$url" | sed -n 's/.*[?&]username=\([^&]*\).*/\1/p')
    stripped_pin=$(echo "$url" | sed -n 's/.*[?&]pin=\([^&]*\).*/\1/p')
    [ -n "$DEBUG_MODE" ] && [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Extracted username=[$stripped_user], pin=[$stripped_pin]" >&2
    local clean_url
    clean_url=$(echo "$url" | sed 's/[?&]username=[^&]*//g;s/[?&]pin=[^&]*//g;s/&&/\&/g;s/?&/?/g;s/&$//;s/?$//')
    echo "$clean_url $stripped_user $stripped_pin"
}

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
                echo "USERNAME=$list_user" > "$conf_file.tmp"
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

purge_blocklist() {
    echo "Purging blocklist setup..."
    echo "Need sudo to remove iptables rule and ipset."
    sudo iptables -D INPUT -m set --match-set blacklist src -j DROP 2>/dev/null
    sudo ipset destroy blacklist 2>/dev/null
    echo "iptables rule and ipset removed."
    read -p "Also delete all configs and credentials? (y/N): " delete_all
    if [[ "$delete_all" =~ ^[Yy]$ ]]; then
        echo "Need sudo to remove $CRED_FILE if owned by root."
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
                        echo "Need sudo to delete $conf_file (owned by root)."
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

load_credentials() {
    if [ -f "$CRED_FILE" ] && [ -r "$CRED_FILE" ]; then
        source "$CRED_FILE"
    fi
}

process_blocklist() {
    local conf_file="$1"
    local temp_list="/tmp/iplist_$(basename "$conf_file").txt"

    unset URL USERNAME PIN
    if [ -r "$conf_file" ]; then
        source <(grep '^URL=\|^USERNAME=\|^PIN=' "$conf_file")
    else
        echo "Cannot read $conf_file: permission denied"
        return 1
    fi
    if [ -z "$URL" ]; then
        echo "Skipping $conf_file: Invalid or empty URL"
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
    URL="$clean_url"
    if [ -z "$URL" ]; then
        echo "Skipping $conf_file: Invalid URL after sanitization"
        return 1
    fi
    if [ -z "$USERNAME" ] && [ -f "$CRED_FILE" ] && [ -r "$CRED_FILE" ]; then
        source "$CRED_FILE"
    fi

    local fetch_url="$URL"
    if [ -n "$USERNAME" ] && [ -n "$PIN" ]; then
        if [[ "$fetch_url" =~ \? ]]; then
            fetch_url="${fetch_url}&username=${USERNAME}&pin=${PIN}"
        else
            fetch_url="${fetch_url}?username=${USERNAME}&pin=${PIN}"
        fi
    fi

    [ -n "$DEBUG_MODE" ] && [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Fetching URL: $fetch_url" >&2
    if ! wget -nv --timeout=10 --tries=2 -O "$IP_LIST_RAW" "$fetch_url"; then
        echo "Failed to download $fetch_url (skipping)"
        return 1
    fi
    if [ ! -s "$IP_LIST_RAW" ]; then
        echo "Downloaded file is empty ($fetch_url)"
        return 1
    fi
    [ -n "$DEBUG_MODE" ] && [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Downloaded size: $(stat -c %s "$IP_LIST_RAW") bytes" >&2

    if ! file "$IP_LIST_RAW" | grep -q "gzip compressed data"; then
        echo "Not a valid gzip archive ($fetch_url)"
        return 1
    fi

    if ! gunzip -c "$IP_LIST_RAW" > "$temp_list"; then
        echo "Failed to decompress ($fetch_url)"
        return 1
    fi
    if [ ! -s "$temp_list" ]; then
        echo "Decompressed file is empty ($fetch_url)"
        return 1
    fi
    [ -n "$DEBUG_MODE" ] && [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Decompressed size: $(stat -c %s "$temp_list") bytes" >&2
    [ -n "$DEBUG_MODE" ] && [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: First 10 lines of $temp_list:" >&2
    [ -n "$DEBUG_MODE" ] && [ "$DEBUG_MODE" -eq 1 ] && head -n 10 "$temp_list" >&2

    local cidr_count
    cidr_count=$(awk '/^([0-9]{1,3}\.){3}[0-9]{1,3}(\/[0-9]{1,2}|-([0-9]{1,3}\.){3}[0-9]{1,3}|$)/ {
        if ($1 ~ /\//) {
            split($1, a, "/");
            ip = a[1];
            mask = a[2];
            if (mask >= 1 && mask <= 32) {
                print $1
            }
        } else if ($1 ~ /-/) {
            print $1
        } else {
            print $1 "/32"
        }
    }' "$temp_list" | tee -a "$IP_LIST" | wc -l)
    [ -n "$DEBUG_MODE" ] && [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Found $cidr_count CIDRs in $temp_list" >&2
}

update_blocklist() {
    setup_config_dir
    if [ ! -d "$CONFIG_DIR" ] || ! ls "$CONFIG_DIR"/*.conf >/dev/null 2>&1; then
        echo "No blocklist configs found in $CONFIG_DIR. Use --config to add one."
        exit 1
    fi

    : > "$IP_LIST"

    total_cidr=0
    dupes=0
    for conf_file in "$CONFIG_DIR"/*.conf; do
        if [ -f "$conf_file" ]; then
            echo "Processing $conf_file..."
            if process_blocklist "$conf_file"; then
                cidrs=$(grep -cE '^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2}|-([0-9]{1,3}\.){3}[0-9]{1,3}|$)' "$IP_LIST")
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
    dupes=$(awk '/^([0-9]{1,3}\.){3}[0-9]{1,3}(\/[0-9]{1,2}|-([0-9]{1,3}\.){3}[0-9]{1,3}|$)/ {print $1}' "$IP_LIST" | sort -n -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4 | uniq -d | wc -l)
    echo "$dupes"
    echo "------------------------"

    echo "Need sudo to remove existing iptables rule and ipset."
    sudo iptables -D INPUT -m set --match-set blacklist src -j DROP 2>/dev/null
    sudo ipset destroy blacklist 2>/dev/null

    if ! sudo ipset create blacklist hash:net hashsize 65536; then
        echo "Failed to create ipset 'blacklist'"
        exit 1
    fi

    echo "flush blacklist" > "$IPSET_RESTORE_FILE"
    awk '/^([0-9]{1,3}\.){3}[0-9]{1,3}(\/[0-9]{1,2}|-([0-9]{1,3}\.){3}[0-9]{1,3}|$)/ {
        if ($1 ~ /\//) {
            split($1, a, "/");
            ip = a[1];
            mask = a[2];
            if (mask >= 1 && mask <= 32) {
                print "add blacklist " $1
            }
        } else if ($1 ~ /-/) {
            split($1, a, "-");
            print "add blacklist " a[1]
        } else {
            print "add blacklist " $1 "/32"
        }
    }' "$IP_LIST" | sort -n -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4 | uniq >> "$IPSET_RESTORE_FILE"

    echo "Applying ipset restore ($((total_cidr - dupes)) unique entries)"
    if ! sudo ipset restore < "$IPSET_RESTORE_FILE"; then
        echo "Failed to apply ipset restore"
        exit 1
    fi

    added=$(sudo ipset list blacklist | grep -c '[0-9]\.[0-9]')
    echo "Added $added entries to blacklist"
    if [ "$added" -lt 40000 ]; then
        echo "Warning: Added fewer entries than expected (<40000)"
    fi

    echo "Need sudo to apply iptables rule."
    if ! sudo iptables -C INPUT -m set --match-set blacklist src -j DROP 2>/dev/null; then
        if ! sudo iptables -I INPUT -m set --match-set blacklist src -j DROP; then
            echo "Failed to apply iptables rule"
            exit 1
        fi
    fi

    echo "Blocklist applied successfully"
}

DEBUG_MODE=0
LOG_MODE=0
ACTIONS=()

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
        *)
            echo "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
    shift
done

if [ "$DEBUG_MODE" -eq 1 ]; then
    set -x
fi

if [ "$LOG_MODE" -eq 1 ]; then
    exec > >(tee -a "$LOG_FILE") 2>&1
    echo "Logging to $LOG_FILE"
fi

if [ ${#ACTIONS[@]} -eq 0 ]; then
    ACTIONS+=("update")
fi

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
            update_blocklist
            ;;
    esac
done
