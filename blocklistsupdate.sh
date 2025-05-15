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

# Supports iptables/nftables, IPv4/IPv6, multiple blocklist sources, and configurable settings
# Version 4.5.1: Added --config-dir option, fixed sudo config path, improved wget handling

# Inspired from https://lowendspirit.com/discussion/7699/use-a-blacklist-of-bad-ips-on-your-linux-firewall-tutorial
# Credit to user itsdeadjim ( https://lowendspirit.com/profile/itsdeadjim )
# The original version of the script by itsdeadjim is referred to as 0.5 if it is uploaded

# Load configuration file, generating it if it doesn't exist (Modified: Added NON_INTERACTIVE_SKIP_MERGE)
load_config() {
    if [ -n "$CONFIG_DIR_OVERRIDE" ]; then
        CONFIG_DIR="$CONFIG_DIR_OVERRIDE/.blocklists"
        CRED_FILE="$CONFIG_DIR_OVERRIDE/.blocklistcredentials.conf"
        LOG_FILE="$CONFIG_DIR_OVERRIDE/blocklistsupdate.log"
        HELP_FILE="$CONFIG_DIR_OVERRIDE/blocklist_readme.md"
        CONFIG_FILE="$CONFIG_DIR_OVERRIDE/.blocklist.conf"
    else
        CONFIG_FILE="$HOME/.blocklist.conf"
    fi
    if [ ! -f "$CONFIG_FILE" ]; then
        # Generate default config with comments
        cat > "$CONFIG_FILE" << 'EOF'
# Blocklist script configuration file
# Note: If using --config-dir, paths below are relative to that directory
# For example, if --config-dir=/home/user, CONFIG_DIR becomes /home/user/.blocklists
# To use absolute paths, edit these settings after the file is created
# To use the defaults without --config-dir, leave as-is
# Paths are relative to $HOME unless --config-dir is specified
# Edit these settings to customize paths, names, and behaviors

# Directory for blocklist configuration files
CONFIG_DIR=$HOME/.blocklists

# Path to credentials file
CRED_FILE=$HOME/.blocklistcredentials.conf

# Path to log file (used with --log)
LOG_FILE=$HOME/blocklistsupdate.log

# Name of the ipset or nftables set
IPSET_NAME=blacklist

# iptables chain to apply rules (e.g., INPUT, FORWARD)
IPTABLES_CHAIN=INPUT

# Firewall backend: iptables or nftables
FIREWALL_BACKEND=iptables

# Number of retry attempts for downloading blocklists
RETRY_ATTEMPTS=3

# Delay between retry attempts in seconds
RETRY_DELAY=5

# Disable CIDR merging for performance (y/n)
NO_IPV4_MERGE=n
NO_IPV6_MERGE=n

# Non-interactive mode defaults (used with --non-interactive)
# Set to 'y' or 'n' to control behavior without prompts
NON_INTERACTIVE_EDIT_CREDENTIALS=n
NON_INTERACTIVE_LOG_IPV6=n
NON_INTERACTIVE_CAP_HASHSIZE=n
NON_INTERACTIVE_CONTINUE_IPTABLES=y
NON_INTERACTIVE_CONTINUE_NO_BACKUP=n
NON_INTERACTIVE_SKIP_MERGE=n
EOF
        chmod 600 "$CONFIG_FILE"
    fi
    # Source config file
    if [ -r "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE"
    else
        echo "Error: Cannot read $CONFIG_FILE"
        exit 1
    fi
}

# Generate blocklist_readme.md if it doesn't exist

HELP_FILE="$HOME/blocklist_readme.md"
if [ ! -f "$HELP_FILE" ]; then
    # Generate help file
    if ! touch "$HELP_FILE" 2>/dev/null; then
        echo "Error: Cannot write to $HELP_FILE"
        exit 1
    fi
    cat > "$HELP_FILE" << 'EOF'
# Blocklist Update Script
Manages IPv4/IPv6 blocklists for Linux firewalls using iptables/ipset or nftables.

## Features
- Downloads and merges blocklists from multiple sources with validation and deduplication.
- Supports iptables/ipset and nftables backends for flexible firewall integration.
- Configurable via `~/.blocklist.conf` and per-source `~/.blocklists/*.conf`.
- Fast rule toggling with `--clear-rules` and `--apply-rules` (reuses ipsets for instant application).
- Credential management for authenticated blocklists (`--auth`).
- Progress bars with `pv`, syntax checks, and detailed debugging (`--debug`, `--verbosedebug`).
- Non-interactive mode and cron support for automation.
- Robust IPv4/IPv6 CIDR merging, with optional `aggregate`/`aggregate6` for speed.

## Installation
On a Debian-based system, install dependencies and prepare the script:

```bash
sudo apt-get install wget gunzip awk iptables ipset
# Optional for progress bars and faster merging
sudo apt-get install pv aggregate aggregate6
chmod +x blocklistsupdatev2.sh
```

Notes:
- Replace iptables ipset with nftables if using --backend nftables.

- pv enables progress bars; aggregate/aggregate6 speed up merging for large blocklists (>10,000 CIDRs).

- Place the script (or create a symlink with `ln -s TARGET LINK_NAME`) in /usr/local/bin/ for system-wide access (optional).

## Usage
1. Configure blocklist sources:
`./blocklistsupdatev2.sh --config`
1. Update and apply blocklists:
`./blocklistsupdatev2.sh`
1. Toggle rules without rebuilding ipsets:
`./blocklistsupdatev2.sh --clear-rules`
`./blocklistsupdatev2.sh --apply-rules`
1. View full options:
`./blocklistsupdatev2.sh --help`

## Configuration
- Edit `~/.blocklist.conf` for defaults (e.g., `CONFIG_DIR`, `IPSET_NAME`).

- Add blocklist sources in `~/.blocklists/*.conf` with `URL` and (if needed) `USERNAME`, `PIN`.

- Use `--auth` to manage credentials for authenticated sources.
EOF
fi

# Check start time for run time calculation
START_TIME=$(date +%s)

# Create secure temporary files
setup_temp_files() {
    if ! [ -w /tmp ]; then
    echo "Error: /tmp is not writable"
    exit 1
    fi
    IP_LIST_RAW=$(mktemp /tmp/iplist_raw.XXXXXX) || { echo "Error: Failed to create temp file"; exit 1; }
    IP_LIST=$(mktemp /tmp/iplist.XXXXXX) || { echo "Error: Failed to create temp file"; exit 1; }
    IPSET_BACKUP_FILE=$(mktemp /tmp/ipset_backup.XXXXXX) || { echo "Error: Failed to create temp file"; exit 1; }
    chmod 600 "$IP_LIST_RAW" "$IP_LIST" "$IPSET_BACKUP_FILE"
}

# Cleanup temporary files on exit
cleanup() {
    rm -f "$IP_LIST_RAW" "$IP_LIST" "$IPSET_RESTORE_FILE" "$IPSET_BACKUP_FILE" /tmp/iplist_*.conf.* /tmp/iplist_raw.* /tmp/iplist.* /tmp/ipset_commands.* /tmp/cidr_list.* /tmp/aggregated_cidr_list.* /tmp/wget_output /tmp/pv_output
    [ "$DEBUG_MODE" -eq 1 ] && echo "Script exited at: $(date)"
}

# Display usage information
show_help() {
    echo "Blocklist management script for Linux firewalls (iptables/nftables, IPv4/IPv6)"
    echo "Usage: $0 [OPTIONS]"
    echo "Options:"
    echo "  --help        Display this help message"
    echo "  --config      Manage blocklist config files (add, edit, delete, view)"
    echo "  --auth        Edit or clear credentials"
    echo "  --config-dir  Override default config directory (~/.blocklists)"
    echo "  --purge       Remove blocklist rules and ipsets; optionally delete configs"
    echo "  --clear-rules Remove blocklist rules, keeping ipsets for fast reapplication"
    echo "  --apply-rules Re-apply blocklist rules from configs"
    echo "  --debug       Enable debug output (includes syntax check)"
    echo "  --verbosedebug Enables --debug, and adds full tracing"
    echo "  --log         Log output to $LOG_FILE"
    echo "  --dry-run     Simulate blocklist update without changes"
    echo "  --ipv6        Process IPv6 addresses (default: IPv4 only)"
    echo "  --no-ipv4-merge  Disable IPv4 CIDR merging (faster, risks overlaps)"
    echo "  --no-ipv6-merge  Disable IPv6 CIDR merging (faster, risks overlaps)"
    echo "  --backend     Set firewall backend (iptables/nftables, default: $FIREWALL_BACKEND)"
    echo "  --non-interactive  Suppress prompts, use config defaults"
    echo "  --ipset-test  Check for duplicates in ipset (adds ~5-10 seconds for 1,500 duplicates)"
    echo "Requirements:"
    echo "  - Required: wget, gunzip, awk, and either (iptables and ipset) or nftables"
    echo "  - Recommended: pv (progress bars), aggregate/aggregate6 (faster merging)"
    echo "Notes:"
    echo "  - Configs stored in $CONFIG_DIR/*.conf"
    echo "  - Large blocklists (>10,000 CIDRs) may be slow without aggregate"
    echo "  - Use --no-ipv4-merge/--no-ipv6-merge for speed if overlaps are acceptable"
}

# Check for required dependencies
check_dependencies() {
    local cmds="wget gunzip awk"
    if [ "$FIREWALL_BACKEND" = "iptables" ]; then
        cmds="$cmds iptables ipset"
    elif [ "$FIREWALL_BACKEND" = "nftables" ]; then
        cmds="$cmds nft"
    fi
    if ! command -v sudo >/dev/null; then
        echo "Error: 'sudo' command not found"
        exit 1
    fi
    for cmd in $cmds; do
        if ! command -v "$cmd" >/dev/null; then
            echo "Error: Required command '$cmd' not found. The script may not function without it."
            exit 1
        fi
    done
    # Optional tools
    for cmd in unzip 7z aggregate aggregate6 pv; do
        if ! command -v "$cmd" >/dev/null; then
            if [ "$cmd" = "pv" ]; then
                echo "Warning: 'pv' not found; progress bars for downloads, parsing, and CIDR application will not be displayed"
            elif [ "$cmd" = "aggregate" ]; then
                echo "Warning: 'aggregate' not found; falling back to slower Bash-based IPv4 CIDR merging. Use --no-ipv4-merge to skip."
            elif [ "$cmd" = "aggregate6" ]; then
                echo "Warning: 'aggregate6' not found; falling back to slower Bash-based IPv6 CIDR merging. Use --no-ipv6-merge to skip."
            else
                echo "Warning: '$cmd' not found; some features may be limited"
            fi
        fi
    done
    # Kernel module check for ipset
    if [ "$FIREWALL_BACKEND" = "iptables" ]; then
        if ! modprobe ip_set >/dev/null 2>&1; then
            echo "Warning: ipset kernel module not available"
        fi
    fi
}

# Verify sudo access, offering re-launch if sudo isn't passwordless
check_sudo() {
    if [ "$EUID" -eq 0 ]; then
        [ -z "$CONFIG_DIR_OVERRIDE" ] && CONFIG_DIR_OVERRIDE="$HOME"
        # Already running as root (sudo)
        return 0
    fi

    # Check if sudo is available without prompting
    if sudo -n true 2>/dev/null; then
        return 0
    fi

    # Interactive mode: Offer choice to re-launch or prompt as needed
    if [ "$NON_INTERACTIVE" -eq 0 ] && [ -z "$CRON" ]; then
        echo "This script requires sudo access."
        read -p "Enter password as needed (p) or re-launch using sudo for uninterrupted runs (R or Enter)?: " choice
        [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: User chose sudo path: ${choice:-R}" >&2
        if [[ "$choice" =~ ^[Rr]$ || -z "$choice" ]]; then
            echo "Re-launching with sudo..."
            # Preserve original arguments
            exec sudo "$0" --config-dir="$HOME" "$@"
        else
            echo "Will prompt for sudo password when needed."
            if sudo true; then
                return 0
            else
                echo "Error: Sudo authentication failed"
                exit 1
            fi
        fi
    else
        echo "Error: Sudo access required (non-interactive mode requires passwordless sudo)"
        exit 1
    fi
}

# Set up configuration directory
setup_config_dir() {
    if [ -n "$CONFIG_DIR_OVERRIDE" ]; then
        CONFIG_DIR="$CONFIG_DIR_OVERRIDE/.blocklists"
    fi
    if [ ! -d "$CONFIG_DIR" ]; then
        mkdir -p "$CONFIG_DIR"
        chmod 700 "$CONFIG_DIR"
    elif [ ! -w "$CONFIG_DIR" ]; then
        echo "Warning: $CONFIG_DIR is not writable"
    fi
        for conf_file in "$CONFIG_DIR"/*.conf; do
        if [ -f "$conf_file" ] && ! grep -q '^URL=' "$conf_file"; then
            echo "Warning: $conf_file missing URL; it will be skipped"
        fi
    done
}

# Manage credentials
manage_credentials() {
    if [ "$NON_INTERACTIVE" -eq 1 ]; then
        if [ "$NON_INTERACTIVE_EDIT_CREDENTIALS" != "y" ]; then
            echo "Skipping credential edit in non-interactive mode"
            return
        fi
    fi
    echo "Current credentials ($CRED_FILE):"
    if [ -f "$CRED_FILE" ] && [ -r "$CRED_FILE" ]; then
        cat "$CRED_FILE"
    else
        echo "(None)"
    fi
    echo
    if [ "$NON_INTERACTIVE" -eq 1 ]; then
        return
    fi
    read -p "Edit credentials? (y/N): " edit
    if [[ "$edit" =~ ^[Yy]$ ]]; then
        read -p "Enter username (blank for none): " username
        read -p "Enter PIN (blank for none): " pin
        if [ -z "$username" ] && [ -z "$pin" ]; then
            if [ -f "$CRED_FILE" ]; then
                [ -w "$CRED_FILE" ] && rm "$CRED_FILE" || sudo rm "$CRED_FILE"
                echo "Credentials cleared"
            fi
        else
            if ! touch "$CRED_FILE" 2>/dev/null; then
                echo "Error: Cannot write to $CRED_FILE"
                exit 1
            fi
            echo "USERNAME=$username" > "$CRED_FILE"
            echo "PIN=$pin" >> "$CRED_FILE"
            chmod 600 "$CRED_FILE"
            echo "Credentials updated"
        fi
    fi
}

# Sanitize config name
sanitize_conf_name() {
    echo "${1%.conf}"
}

# Sanitize URL, extracting credentials
sanitize_url() {
    local url="$1"
    local stripped_user stripped_pin
    stripped_user=$(echo "$url" | sed -n 's/.*[?&]username=\([^&]*\).*/\1/p')
    stripped_pin=$(echo "$url" | sed -n 's/.*[?&]pin=\([^&]*\).*/\1/p')
    [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Extracted username=[$stripped_user], pin=[$stripped_pin]" >&2
    local clean_url
    clean_url=$(echo "$url" | sed 's/[?&]username=[^&]*//g;s/[?&]pin=[^&]*//g;s/&&/\&/g;s/?&/?/g;s/&$//;s/?$//')
    if ! echo "$clean_url" | grep -q "fileformat="; then
        clean_url="${clean_url}&fileformat=cidr"
    fi
    if ! echo "$clean_url" | grep -q "archiveformat="; then
        clean_url="${clean_url}&archiveformat=gz"
    fi
    printf "%s|%s|%s\n" "$clean_url" "$stripped_user" "$stripped_pin"
}

# Manage blocklist configs
manage_configs() {
    setup_config_dir
    echo "Current configs in $CONFIG_DIR:"
    ls -1 "$CONFIG_DIR" | grep '\.conf$' | sed 's/\.conf$//' || echo "(None)"
    echo
    echo "Options: (a)dd, (e)dit, (v)iew, (d)elete one, (D)elete all, (q)uit"
    read -p "Choose action: " action
    case "$action" in
        a|A)
            read -p "Enter config name: " name
            name=$(sanitize_conf_name "$name")
            [ -z "$name" ] && { echo "Name required"; exit 1; }
            read -p "Enter blocklist URL: " url
            [ -z "$url" ] && { echo "URL required"; exit 1; }
            local clean_url stripped_user stripped_pin
            read clean_url stripped_user stripped_pin < <(sanitize_url "$url" | tr '|' ' ')
            local list_user list_pin
            if [ -n "$stripped_user" ] || [ -n "$stripped_pin" ]; then
                echo "Found credentials in URL:"
                echo "Username: $stripped_user"
                echo "PIN: $stripped_pin"
                read -p "Add to config? (y/N): " auto_add
                if [[ "$auto_add" =~ ^[Yy]$ ]]; then
                    list_user="$stripped_user"
                    list_pin="$stripped_pin"
                fi
            fi
            [ -z "$list_user" ] && read -p "Enter username (blank for $CRED_FILE): " list_user
            [ -z "$list_pin" ] && read -p "Enter PIN (blank for $CRED_FILE): " list_pin
            conf_file="$CONFIG_DIR/$name.conf"
            echo "URL=$clean_url" > "$conf_file"
            [ -n "$list_user" ] && echo "USERNAME=$list_user" >> "$conf_file"
            [ -n "$list_pin" ] && echo "PIN=$list_pin" >> "$conf_file"
            chmod 600 "$conf_file"
            echo "Added $conf_file"
            ;;
        e|E)
            read -p "Enter config name: " name
            name=$(sanitize_conf_name "$name")
            conf_file="$CONFIG_DIR/$name.conf"
            [ ! -f "$conf_file" ] && { echo "Config not found"; exit 1; }
            echo "Current config ($conf_file):"
            [ -r "$conf_file" ] && cat "$conf_file" || echo "(Permission denied)"
            read -p "Enter new URL (blank to keep): " url
            local clean_url stripped_user stripped_pin
            if [ -n "$url" ]; then
                read clean_url stripped_user stripped_pin < <(sanitize_url "$url" | tr '|' ' ')
                if [ -n "$stripped_user" ] || [ -n "$stripped_pin" ]; then
                    echo "Found credentials in URL:"
                    echo "Username: $stripped_user"
                    echo "PIN: $stripped_pin"
                    read -p "Add to config? (y/N): " auto_add
                    if [[ "$auto_add" =~ ^[Yy]$ ]]; then
                        list_user="$stripped_user"
                        list_pin="$stripped_pin"
                    fi
                fi
            fi
            [ -z "$list_user" ] && read -p "Enter new username (blank to keep): " list_user
            [ -z "$list_pin" ] && read -p "Enter new PIN (blank to keep): " list_pin
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
            read -p "Enter config name: " name
            name=$(sanitize_conf_name "$name")
            conf_file="$CONFIG_DIR/$name.conf"
            [ ! -f "$conf_file" ] && { echo "Config not found"; exit 1; }
            echo "Config ($conf_file):"
            [ -r "$conf_file" ] && cat "$conf_file" || echo "(Permission denied)"
            ;;
        D)
            read -p "Delete ALL configs? (y/N): " confirm
            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                configs_found=0
                for conf_file in "$CONFIG_DIR"/*.conf; do
                    if [ -f "$conf_file" ]; then
                        configs_found=1
                        conf_name=$(basename "$conf_file" .conf)
                        echo "- $conf_name"
                        [ -w "$conf_file" ] && rm "$conf_file" || sudo rm "$conf_file"
                    fi
                done
                [ "$configs_found" -eq 0 ] && echo "(No configs found)" || echo "All configs deleted"
            fi
            ;;
        d)
            read -p "Enter config name: " name
            name=$(sanitize_conf_name "$name")
            conf_file="$CONFIG_DIR/$name.conf"
            [ ! -f "$conf_file" ] && { echo "Config not found"; exit 1; }
            [ -w "$conf_file" ] && rm "$conf_file" || sudo rm "$conf_file"
            echo "Deleted $conf_file"
            ;;
        q|Q)
            exit 0
            ;;
        *)
            echo "Invalid action"
            exit 1
            ;;
    esac
}

# Purge blocklist setup
purge_blocklist() {
    check_sudo
    echo "Removing blocklist rules and ipsets..."
    if [ "$FIREWALL_BACKEND" = "iptables" ]; then
        sudo iptables -D "$IPTABLES_CHAIN" -m set --match-set "$IPSET_NAME" src -j DROP 2>/dev/null
        [ "$IPV6_ENABLED" -eq 1 ] && sudo ip6tables -D "$IPTABLES_CHAIN" -m set --match-set "${IPSET_NAME}_v6" src -j DROP 2>/dev/null
        sudo ipset destroy "$IPSET_NAME" 2>/dev/null
        [ "$IPV6_ENABLED" -eq 1 ] && sudo ipset destroy "${IPSET_NAME}_v6" 2>/dev/null
    else
        sudo nft delete rule ip filter "$IPTABLES_CHAIN" handle $(sudo nft -a list chain ip filter "$IPTABLES_CHAIN" | grep "set $IPSET_NAME" | awk '{print $NF}') 2>/dev/null
        [ "$IPV6_ENABLED" -eq 1 ] && sudo nft delete rule ip6 filter "$IPTABLES_CHAIN" handle $(sudo nft -a list chain ip6 filter "$IPTABLES_CHAIN" | grep "set ${IPSET_NAME}_v6" | awk '{print $NF}') 2>/dev/null
        sudo nft delete set ip filter "$IPSET_NAME" 2>/dev/null
        [ "$IPV6_ENABLED" -eq 1 ] && sudo nft delete set ip6 filter "${IPSET_NAME}_v6" 2>/dev/null
    fi
    if [ "$NON_INTERACTIVE" -eq 0 ]; then
        echo "Blocklist rules and ipsets removed; configs and credentials preserved by default."
        read -p "Also delete configs and credentials in $CONFIG_DIR? (y/N): " delete_configs
        if [[ "$delete_configs" =~ ^[Yy]$ ]]; then
            rm -rf "$CONFIG_DIR" "$CRED_FILE"
            echo "Configs and credentials deleted"
        else
            echo "Configs and credentials kept"
        fi
    else
        echo "Non-interactive mode: Configs and credentials preserved"
    fi
    echo "Blocklist purge complete"
}

# Clear blocklist rules from firewall
clear_rules() {
    check_sudo
    if [ "$NON_INTERACTIVE" -eq 0 ]; then
        echo "This will remove blocklist firewall rules, keeping ipsets and configs for fast reapplication."
        read -p "Continue? (y/N): " confirm_clear
        if [[ ! "$confirm_clear" =~ ^[Yy]$ ]]; then
            echo "Clearing aborted"
            return 0
        fi
    fi
    echo "Clearing blocklist firewall rules..."
    if [ "$FIREWALL_BACKEND" = "iptables" ]; then
        sudo iptables -D "$IPTABLES_CHAIN" -m set --match-set "$IPSET_NAME" src -j DROP 2>/dev/null
        [ "$IPV6_ENABLED" -eq 1 ] && sudo ip6tables -D "$IPTABLES_CHAIN" -m set --match-set "${IPSET_NAME}_v6" src -j DROP 2>/dev/null
    else
        sudo nft delete rule ip filter "$IPTABLES_CHAIN" handle $(sudo nft -a list chain ip filter "$IPTABLES_CHAIN" | grep "set $IPSET_NAME" | awk '{print $NF}') 2>/dev/null
        [ "$IPV6_ENABLED" -eq 1 ] && sudo nft delete rule ip6 filter "$IPTABLES_CHAIN" handle $(sudo nft -a list chain ip6 filter "$IPTABLES_CHAIN" | grep "set ${IPSET_NAME}_v6" | awk '{print $NF}') 2>/dev/null
    fi
    echo "Blocklist firewall rules cleared; ipsets preserved for fast reapplication"
}

# Load credentials
load_credentials() {
    if [ -f "$CRED_FILE" ] && [ -r "$CRED_FILE" ]; then
        USERNAME=$(grep '^USERNAME=' "$CRED_FILE" | cut -d= -f2-)
        PIN=$(grep '^PIN=' "$CRED_FILE" | cut -d= -f2-)
    fi
}

# Validate CIDR format
validate_cidr() {
    local range="$1" family="$2"
    if [ "$family" = "inet" ]; then
        # Validate IPv4 CIDR
        if [[ "$range" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]]; then
            local ip mask
            IFS='/' read -r ip mask <<< "$range"
            [ -z "$mask" ] && mask=32
            IFS='.' read -r a b c d <<< "$ip"
            for octet in $a $b $c $d; do
                [ "$octet" -gt 255 ] || [ "$octet" -lt 0 ] && return 1
            done
            [ "$mask" -ge 1 ] && [ "$mask" -le 32 ] && return 0
        fi
    elif [ "$family" = "inet6" ]; then
        # Validate IPv6 CIDR (basic check for hex and mask)
        if [[ "$range" =~ ^[0-9a-fA-F:]+(/[0-9]{1,3})?$ ]]; then
            local ip mask
            IFS='/' read -r ip mask <<< "$range"
            [ -z "$mask" ] && mask=128
            [ "$mask" -ge 1 ] && [ "$mask" -le 128 ] && return 0
        fi
    fi
    return 1
}

# Download blocklist with retry logic
download_blocklist() {
    local fetch_url="$1" temp_raw="$2"
    # Attempt download with retries
    for attempt in $(seq 1 "$RETRY_ATTEMPTS"); do
        [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Attempt $attempt: wget $fetch_url" >&2
        local wget_cmd="wget -nv -L --timeout=10 --tries=1 -O $temp_raw $fetch_url"
        if command -v pv >/dev/null; then
            # Use pv to show download progress
            if $wget_cmd 2>/tmp/wget_output && [ -s "$temp_raw" ]; then
                pv -f -N "Downloading $fetch_url" "$temp_raw" > /dev/null 2>/tmp/pv_output
                return 0
            fi
        else
            # Fallback to wget without pv
            if $wget_cmd 2>/tmp/wget_output && [ -s "$temp_raw" ]; then
                return 0
            fi
        fi
        local wget_error=$(cat /tmp/wget_output)
        if echo "$wget_error" | grep -q "403 Forbidden"; then
            echo "Authentication failed for $fetch_url" | tee -a "$LOG_FILE"
            rm -f /tmp/wget_output /tmp/pv_output
            return 1
        elif echo "$wget_error" | grep -q "429 Too Many Requests"; then
            echo "Rate limit exceeded for $fetch_url" | tee -a "$LOG_FILE"
        else
            echo "Download attempt $attempt failed: $wget_error" | tee -a "$LOG_FILE"
        fi
        [ "$attempt" -lt "$RETRY_ATTEMPTS" ] && { echo "Retrying in $RETRY_DELAY seconds..."; sleep "$RETRY_DELAY"; }
    done
    echo "Failed to download $fetch_url after $RETRY_ATTEMPTS attempts"
    rm -f /tmp/wget_output /tmp/pv_output
    return 1
}

# Parse blocklist file
parse_blocklist() {
    local conf_file="$1" temp_list="$2"
    local cidr_count=0 skipped_empty=0 skipped_comments=0 batch=""
    # Debug: Show first 5 lines to inspect file format
    [ "$DEBUG_MODE" -eq 1 ] && {
        echo "DEBUG: First 5 lines of $temp_list:" >&2
        head -n 5 "$temp_list" >&2
    }
    # Get total lines for pv progress
    local total_lines=$(wc -l < "$temp_list")
    # Parse each line, handling comments, blanks, and CIDRs
    if command -v pv >/dev/null; then
        # Use pv to show parsing progress
        while IFS= read -r line || [ -n "$line" ]; do
            # Check for comments and empty lines before trimming
            [[ "$line" =~ ^[[:space:]]*$ ]] && {
                [ "$VERBOSE_DEBUG" -eq 1 ] && echo "DEBUG: Skipping empty line in $conf_file" >&2
                skipped_empty=$((skipped_empty + 1))
                continue
            }
            [[ "$line" =~ ^[[:space:]]*# ]] && {
                [ "$VERBOSE_DEBUG" -eq 1 ] && echo "DEBUG: Skipping comment: $line" >&2
                skipped_comments=$((skipped_comments + 1))
                continue
            }
            # Trim leading/trailing whitespace
            range=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
            # Try name:range format
            if [[ "$range" =~ ^[^:]+:([0-9a-fA-F.:/]+)$ ]]; then
                range="${BASH_REMATCH[1]}"
            fi
            # Check if IPv4 CIDR (e.g., 192.168.1.0/24)
            if [[ "$range" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]]; then
                range="${range%/32}" # Normalize single IPs
                if validate_cidr "$range" inet; then
                    # Ensure consistent format (always add /32 for single IPs)
                    if [[ ! "$range" =~ /[0-9]+$ ]]; then
                        range="$range/32"
                    fi
                    batch="$batch\ninet $range"
                    cidr_count=$((cidr_count + 1))
                    [ "$DEBUG_MODE" -eq 1 ] && [ $((cidr_count % 10000)) -eq 0 ] && echo "DEBUG: Processed $cidr_count CIDRs in $conf_file" >&2
                else
                    echo "Invalid IPv4 CIDR in $conf_file: $range"
                fi
            # Check if IPv6 CIDR (e.g., 2001:db8::/64)
            elif [ "$IPV6_ENABLED" -eq 1 ] && [[ "$range" =~ ^[0-9a-fA-F:]+(/[0-9]{1,3})?$ ]]; then
                range="${range%/128}" # Normalize single IPs
                if validate_cidr "$range" inet6; then
                    # Ensure consistent format (always add /128 for single IPs)
                    if [[ ! "$range" =~ /[0-9]+$ ]]; then
                        range="$range/128"
                    fi
                    batch="$batch\ninet6 $range"
                    cidr_count=$((cidr_count + 1))
                    [ "$DEBUG_MODE" -eq 1 ] && [ $((cidr_count % 10000)) -eq 0 ] && echo "DEBUG: Processed $cidr_count CIDRs in $conf_file" >&2
                else
                    echo "Invalid IPv6 CIDR in $conf_file: $range"
                fi
            elif [[ "$range" =~ ^[0-9a-fA-F:]+(/[0-9]{1,3})?$ ]]; then
                if [ "$NON_INTERACTIVE" -eq 1 ]; then
                    [ "$NON_INTERACTIVE_LOG_IPV6" = "y" ] && echo "$range" >> "$LOG_FILE.ipv6"
                else
                    read -p "IPv6 detected in $conf_file. Log to $LOG_FILE.ipv6? (y/N): " log_ipv6
                    if [[ "$log_ipv6" =~ ^[Yy]$ ]]; then
                        echo "$range" >> "$LOG_FILE.ipv6"
                        chmod 600 "$LOG_FILE.ipv6" 2>/dev/null
                    fi
                fi
            else
                echo "Skipping non-CIDR in $conf_file: $range"
            fi
            # Write batch every 1,000 lines to balance memory and I/O
            if [ $((cidr_count % 1000)) -eq 0 ]; then
                echo -e "$batch" | sed '/^$/d' >> "$IP_LIST"  # Remove empty lines from batch
                batch=""
            fi
        done < <(pv -f -N "Parsing $conf_file" -s "$total_lines" "$temp_list")
    else
        # Fallback without pv
        while IFS= read -r line || [ -n "$line" ]; do
            # Check for comments and empty lines before trimming
            [[ "$line" =~ ^[[:space:]]*$ ]] && {
                [ "$VERBOSE_DEBUG" -eq 1 ] && echo "DEBUG: Skipping empty line in $conf_file" >&2
                skipped_empty=$((skipped_empty + 1))
                continue
            }
            [[ "$line" =~ ^[[:space:]]*# ]] && {
                [ "$VERBOSE_DEBUG" -eq 1 ] && echo "DEBUG: Skipping comment: $line" >&2
                skipped_comments=$((skipped_comments + 1))
                continue
            }
            # Trim leading/trailing whitespace
            range=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
            # Try name:range format
            if [[ "$range" =~ ^[^:]+:([0-9a-fA-F.:/]+)$ ]]; then
                range="${BASH_REMATCH[1]}"
            fi
            # Check if IPv4 CIDR (e.g., 192.168.1.0/24)
            if [[ "$range" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]]; then
                range="${range%/32}" # Normalize single IPs
                if validate_cidr "$range" inet; then
                    # Ensure consistent format (always add /32 for single IPs)
                    if [[ ! "$range" =~ /[0-9]+$ ]]; then
                        range="$range/32"
                    fi
                    batch="$batch\ninet $range"
                    cidr_count=$((cidr_count + 1))
                    [ "$DEBUG_MODE" -eq 1 ] && [ $((cidr_count % 10000)) -eq 0 ] && echo "DEBUG: Processed $cidr_count CIDRs in $conf_file" >&2
                else
                    echo "Invalid IPv4 CIDR in $conf_file: $range"
                fi
            # Check if IPv6 CIDR (e.g., 2001:db8::/64)
            elif [ "$IPV6_ENABLED" -eq 1 ] && [[ "$range" =~ ^[0-9a-fA-F:]+(/[0-9]{1,3})?$ ]]; then
                range="${range%/128}" # Normalize single IPs
                if validate_cidr "$range" inet6; then
                    # Ensure consistent format (always add /128 for single IPs)
                    if [[ ! "$range" =~ /[0-9]+$ ]]; then
                        range="$range/128"
                    fi
                    batch="$batch\ninet6 $range"
                    cidr_count=$((cidr_count + 1))
                    [ "$DEBUG_MODE" -eq 1 ] && [ $((cidr_count % 10000)) -eq 0 ] && echo "DEBUG: Processed $cidr_count CIDRs in $conf_file" >&2
                else
                    echo "Invalid IPv6 CIDR in $conf_file: $range"
                fi
            elif [[ "$range" =~ ^[0-9a-fA-F:]+(/[0-9]{1,3})?$ ]]; then
                if [ "$NON_INTERACTIVE" -eq 1 ]; then
                    [ "$NON_INTERACTIVE_LOG_IPV6" = "y" ] && echo "$range" >> "$LOG_FILE.ipv6"
                else
                    read -p "IPv6 detected in $conf_file. Log to $LOG_FILE.ipv6? (y/N): " log_ipv6
                    if [[ "$log_ipv6" =~ ^[Yy]$ ]]; then
                        echo "$range" >> "$LOG_FILE.ipv6"
                        chmod 600 "$LOG_FILE.ipv6" 2>/dev/null
                    fi
                fi
            else
                echo "Skipping non-CIDR in $conf_file: $range"
            fi
            # Write batch every 1,000 lines to balance memory and I/O
            if [ $((cidr_count % 1000)) -eq 0 ]; then
                echo -e "$batch" | sed '/^$/d' >> "$IP_LIST"  # Remove empty lines from batch
                batch=""
            fi
        done < "$temp_list"
    fi
    # Write any remaining lines
    [ -n "$batch" ] && echo -e "$batch" | sed '/^$/d' >> "$IP_LIST"
    [ "$DEBUG_MODE" -eq 1 ] && {
        echo "DEBUG: Found $cidr_count CIDRs, skipped $skipped_empty empty lines, $skipped_comments comments in $temp_list" >&2
    }
    echo "Added $cidr_count CIDRs from $conf_file"
    if [ "$cidr_count" -eq 0 ]; then
        echo "Warning: No valid CIDRs found in $conf_file"
    fi
    return 0
}

# Function to convert IPv4 address to decimal
ip_to_decimal() {
    local ip="$1"
    IFS='.' read -r a b c d <<< "$ip"
    echo $(( (a << 24) + (b << 16) + (c << 8) + d ))
}

# Function to convert IPv4 CIDR to start/end decimal range
cidr_to_range() {
    local cidr="$1"
    local ip mask
    IFS='/' read -r ip mask <<< "$cidr"
    [ -z "$mask" ] && mask=32
    local dec_ip=$(ip_to_decimal "$ip")
    local shift=$((32 - mask))
    local start=$((dec_ip & ~( (1 << shift) - 1 )))
    local end=$((start + (1 << shift) - 1))
    echo "$start $end"
}

# Function to merge overlapping IPv4 CIDRs in Bash
merge_cidrs_bash() {
    local input_file="$1" output_file="$2"
    local cidrs=()
    local ranges=()
    local count=0

    # Read CIDRs into array
    while IFS= read -r cidr; do
        [ -z "$cidr" ] && continue
        cidrs+=("$cidr")
    done < "$input_file"

    # Estimate total CIDRs for pv
    local total_cidrs=${#cidrs[@]}
    [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Merging $total_cidrs IPv4 CIDRs" >&2

    # Convert CIDRs to ranges with pv progress
    if command -v pv >/dev/null && [ "$total_cidrs" -gt 0 ]; then
        printf "%s\n" "${cidrs[@]}" | pv -f -N "Merging IPv4 CIDRs" -s "$total_cidrs" | while IFS= read -r cidr; do
            read start end <<< "$(cidr_to_range "$cidr")"
            echo "$start $end $cidr"
            count=$((count + 1))
            [ "$DEBUG_MODE" -eq 1 ] && [ $((count % 10000)) -eq 0 ] && echo "DEBUG: Processed $count CIDRs in $input_file for merging" >&2
        done > "$output_file.tmp.ranges"
    else
        while IFS= read -r cidr; do
            read start end <<< "$(cidr_to_range "$cidr")"
            echo "$start $end $cidr"
            count=$((count + 1))
            [ "$DEBUG_MODE" -eq 1 ] && [ $((count % 10000)) -eq 0 ] && echo "DEBUG: Processed $count CIDRs in $input_file for merging" >&2
        done < <(printf "%s\n" "${cidrs[@]}") > "$output_file.tmp.ranges"
    fi

    # Sort ranges by start address
    sort -n "$output_file.tmp.ranges" > "$output_file.tmp.sorted"

    # Merge overlapping ranges
    local merged=()
    local current_start current_end current_cidr
    read current_start current_end current_cidr < "$output_file.tmp.sorted"
    while IFS= read -r start end cidr; do
        if [ $start -le $((current_end + 1)) ]; then
            # Overlap or adjacent; extend current range if needed
            if [ $end -gt $current_end ]; then
                current_end=$end
                # Prefer the broader CIDR (smaller mask)
                local current_mask=${current_cidr##*/}
                local new_mask=${cidr##*/}
                [ -z "$current_mask" ] && current_mask=32
                [ -z "$new_mask" ] && new_mask=32
                if [ $new_mask -lt $current_mask ]; then
                    current_cidr="$cidr"
                fi
            fi
        else
            # No overlap; save current and move to next
            merged+=("$current_cidr")
            current_start=$start
            current_end=$end
            current_cidr="$cidr"
        fi
    done < <(tail -n +2 "$output_file.tmp.sorted")
    merged+=("$current_cidr")

    # Write merged CIDRs to output
    merged_sorted=($(printf "%s\n" "${merged[@]}" | sort -u))
    printf "%s\n" "${merged_sorted[@]}" > "$output_file"
    rm -f "$output_file.tmp.ranges" "$output_file.tmp.sorted"
}

# Function to convert IPv6 address to decimal using bc
ipv6_to_decimal() {
    local ip="$1"
    # Expand IPv6 address to full format (e.g., ::1 -> 0000:0000:0000:0000:0000:0000:0000:0001)
    local expanded=$(echo "$ip" | awk -F: '{
        n=NF; for(i=1;i<=NF;i++) if($i=="") n++; 
        if(n<8) { 
            for(i=1;i<=NF;i++) { 
                if($i=="") { 
                    for(j=1;j<=9-NF;j++) printf "0000:"; 
                } else { 
                    printf "%04x:",$i 
                } 
            } 
        } else { 
            for(i=1;i<=NF;i++) printf "%04x:",$i 
        }
    }' | sed 's/:$//')
    # Split into 8 hextets
    IFS=':' read -r h1 h2 h3 h4 h5 h6 h7 h8 <<< "$expanded"
    # Convert to decimal using bc
    echo "ibase=16; ($h1 * 2^112) + ($h2 * 2^96) + ($h3 * 2^80) + ($h4 * 2^64) + ($h5 * 2^48) + ($h6 * 2^32) + ($h7 * 2^16) + $h8" | bc
}

# Function to convert IPv6 CIDR to start/end decimal range
cidr_to_range_ipv6() {
    local cidr="$1"
    local ip mask
    IFS='/' read -r ip mask <<< "$cidr"
    [ -z "$mask" ] && mask=128
    local dec_ip=$(ipv6_to_decimal "$ip")
    local shift=$((128 - mask))
    # Use bc for large number calculations
    local mask_val=$(echo "2^$shift - 1" | bc)
    local start=$(echo "$dec_ip - ($dec_ip % (2^$shift))" | bc)
    local end=$(echo "$start + $mask_val" | bc)
    echo "$start $end"
}

# Function to merge overlapping IPv6 CIDRs in Bash
merge_cidrs_bash_ipv6() {
    local input_file="$1" output_file="$2"
    local cidrs=()
    local ranges=()
    local count=0

    # Read CIDRs into array
    while IFS= read -r cidr; do
        [ -z "$cidr" ] && continue
        cidrs+=("$cidr")
    done < "$input_file"

    # Estimate total CIDRs for pv
    local total_cidrs=${#cidrs[@]}
    [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Merging $total_cidrs IPv6 CIDRs" >&2

    # Convert CIDRs to ranges with pv progress
    if command -v pv >/dev/null && [ "$total_cidrs" -gt 0 ]; then
        printf "%s\n" "${cidrs[@]}" | pv -f -N "Merging IPv6 CIDRs" -s "$total_cidrs" | while IFS= read -r cidr; do
            read start end <<< "$(cidr_to_range_ipv6 "$cidr")"
            echo "$start $end $cidr"
            count=$((count + 1))
            [ "$DEBUG_MODE" -eq 1 ] && [ $((count % 10000)) -eq 0 ] && echo "DEBUG: Processed $count CIDRs in $input_file for merging" >&2
        done > "$output_file.tmp.ranges"
    else
        while IFS= read -r cidr; do
            read start end <<< "$(cidr_to_range_ipv6 "$cidr")"
            echo "$start $end $cidr"
            count=$((count + 1))
            [ "$DEBUG_MODE" -eq 1 ] && [ $((count % 10000)) -eq 0 ] && echo "DEBUG: Processed $count CIDRs in $input_file for merging" >&2
        done < <(printf "%s\n" "${cidrs[@]}") > "$output_file.tmp.ranges"
    fi

    # Sort ranges by start address
    sort -n "$output_file.tmp.ranges" > "$output_file.tmp.sorted"

    # Merge overlapping ranges
    local merged=()
    local current_start current_end current_cidr
    read current_start current_end current_cidr < "$output_file.tmp.sorted"
    while IFS= read -r start end cidr; do
        if [ $(echo "$start <= $current_end + 1" | bc) -eq 1 ]; then
            # Overlap or adjacent; extend current range if needed
            if [ $(echo "$end > $current_end" | bc) -eq 1 ]; then
                current_end="$end"
                # Prefer the broader CIDR (smaller mask)
                local current_mask=${current_cidr##*/}
                local new_mask=${cidr##*/}
                [ -z "$current_mask" ] && current_mask=128
                [ -z "$new_mask" ] && new_mask=128
                if [ $new_mask -lt $current_mask ]; then
                    current_cidr="$cidr"
                fi
            fi
        else
            # No overlap; save current and move to next
            merged+=("$current_cidr")
            current_start="$start"
            current_end="$end"
            current_cidr="$cidr"
        fi
    done < <(tail -n +2 "$output_file.tmp.sorted")
    merged+=("$current_cidr")

    # Write merged CIDRs to output
    merged_sorted=($(printf "%s\n" "${merged[@]}" | sort -u))
    printf "%s\n" "${merged_sorted[@]}" > "$output_file"
    rm -f "$output_file.tmp.ranges" "$output_file.tmp.sorted"
}

# Process a single blocklist
process_blocklist() {
    local conf_file="$1"
    local temp_list
    temp_list=$(mktemp /tmp/iplist_$(basename "$conf_file").XXXXXX) || { echo "Error: Failed to create temp file"; return 1; }
    chmod 600 "$temp_list"

    # Parse config
    local URL USERNAME PIN
    URL=$(grep '^URL=' "$conf_file" | cut -d= -f2-)
    USERNAME=$(grep '^USERNAME=' "$conf_file" | cut -d= -f2-)
    PIN=$(grep '^PIN=' "$conf_file" | cut -d= -f2-)
    [ -z "$URL" ] && { echo "Skipping $conf_file: No URL"; rm -f "$temp_list"; return 1; }
    local clean_url stripped_user stripped_pin
    read clean_url stripped_user stripped_pin < <(sanitize_url "$URL" | tr '|' ' ')
    if [ -n "$stripped_user" ] || [ -n "$stripped_pin" ]; then
        echo "Warning: Credentials in $conf_file URL ignored"
    fi
    URL="$clean_url"
    if [ -z "$USERNAME" ] && [ -f "$CRED_FILE" ] && [ -r "$CRED_FILE" ]; then
        USERNAME=$(grep '^USERNAME=' "$CRED_FILE" | cut -d= -f2-)
        PIN=$(grep '^PIN=' "$CRED_FILE" | cut -d= -f2-)
    fi
    local fetch_url="$URL"
    if [ -n "$USERNAME" ] && [ -n "$PIN" ]; then
        if [[ "$fetch_url" =~ \? ]]; then
            fetch_url="${fetch_url}&username=${USERNAME}&pin=${PIN}"
        else
            fetch_url="${fetch_url}?username=${USERNAME}&pin=${PIN}"
        fi
    fi

    # Download
    [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Downloading blocklist from $fetch_url to $IP_LIST_RAW" >&2
    if ! download_blocklist "$fetch_url" "$IP_LIST_RAW"; then
        rm -f "$temp_list"
        return 1
    fi
    [ ! -s "$IP_LIST_RAW" ] && { echo "Downloaded file empty"; rm -f "$temp_list"; return 1; }
    [ "$DEBUG_MODE" -eq 1 ] && {
        local file_size
        if [ "$(uname -s)" = "Linux" ]; then
            file_size=$(stat --format="%s" "$IP_LIST_RAW" 2>/dev/null)
        else
            file_size=$(stat -f %z "$IP_LIST_RAW" 2>/dev/null)
        fi
        echo "DEBUG: Downloaded file size: $file_size bytes" >&2
    }
    [ "$VERBOSE_DEBUG" -eq 1 ] && {
        echo "DEBUG: Detailed file stats:" >&2
        stat "$IP_LIST_RAW" >&2
    }

    # Decompress
    local file_type
    file_type=$(file "$IP_LIST_RAW")
    if echo "$file_type" | grep -q "gzip compressed data"; then
        gunzip -c "$IP_LIST_RAW" > "$temp_list" || { echo "Failed to decompress gzip"; rm -f "$temp_list"; return 1; }
    elif echo "$file_type" | grep -q "Zip archive"; then
        command -v unzip >/dev/null || { echo "Error: unzip required"; rm -f "$temp_list"; return 1; }
        unzip -p "$IP_LIST_RAW" > "$temp_list" || { echo "Failed to decompress zip"; rm -f "$temp_list"; return 1; }
    elif echo "$file_type" | grep -q "7-zip archive"; then
        command -v 7z >/dev/null || { echo "Error: 7z required"; rm -f "$temp_list"; return 1; }
        7z e -so "$IP_LIST_RAW" > "$temp_list" || { echo "Failed to decompress 7z"; rm -f "$temp_list"; return 1; }
    else
        echo "Unsupported archive format"
        rm -f "$temp_list"
        return 1
    fi
    [ ! -s "$temp_list" ] && { echo "Decompressed file empty"; rm -f "$temp_list"; return 1; }

    # Parse
    parse_blocklist "$conf_file" "$temp_list"
    local status=$?
    rm -f "$temp_list"
    return $status
}

# Create ipset or nftables set
create_set() {
    local family="$1" set_name="$2" hashsize="$3"
    if [ "$FIREWALL_BACKEND" = "iptables" ]; then
        # Increase maxelem to 1,048,576 and ensure hashsize is sufficient
        sudo ipset create "$set_name" hash:ip hashsize "$hashsize" family "$family" maxelem 1048576 2>/dev/null
    else
        # Create nftables set
        if [ "$family" = "inet" ]; then
            sudo nft add set ip filter "$set_name" "{ type ipv4_addr; flags interval; }" 2>/dev/null
        else
            sudo nft add set ip6 filter "$set_name" "{ type ipv6_addr; flags interval; }" 2>/dev/null
        fi
    fi
}

# Add CIDRs to set
add_to_set() {
    local family="$1" cidr="$2" set_name="$3"
    if [ "$FIREWALL_BACKEND" = "iptables" ]; then
        echo "add $set_name $cidr"
        [ "$DEBUG_MODE" -eq 1 ] && [ "$cidr_count" -le 5 ] && echo "DEBUG: Adding $cidr to $set_name" >&2
    else
        sudo nft add element ip filter "$set_name" "{ $cidr }" 2>/dev/null || \
        sudo nft add element ip6 filter "$set_name" "{ $cidr }" 2>/dev/null
    fi
}

# Apply set changes
apply_set() {
    local set_name="$1"
    # ipset restore is now handled in update_blocklist
    return 0
}

# Backup existing set
backup_set() {
    local set_name="$1"
    if [ "$FIREWALL_BACKEND" = "iptables" ]; then
        [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Backing up ipset $set_name to $IPSET_BACKUP_FILE" >&2
        sudo ipset save "$set_name" -file "$IPSET_BACKUP_FILE" 2>/dev/null
    else
        [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Backing up nft set $set_name to $IPSET_BACKUP_FILE" >&2
        sudo nft list set ip filter "$set_name" > "$IPSET_BACKUP_FILE" 2>/dev/null || \
        sudo nft list set ip6 filter "$set_name" > "$IPSET_BACKUP_FILE" 2>/dev/null
    fi
}

# Apply firewall rule
apply_rule() {
    local family="$1" set_name="$2"
    if [ "$FIREWALL_BACKEND" = "iptables" ]; then
        if [ "$family" = "inet" ]; then
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Checking/adding iptables rule for $set_name" >&2
            sudo iptables -C "$IPTABLES_CHAIN" -m set --match-set "$set_name" src -j DROP 2>/dev/null || \
            sudo iptables -I "$IPTABLES_CHAIN" -m set --match-set "$set_name" src -j DROP
        else
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Checking/adding ip6tables rule for $set_name" >&2
            sudo ip6tables -C "$IPTABLES_CHAIN" -m set --match-set "$set_name" src -j DROP 2>/dev/null || \
            sudo ip6tables -I "$IPTABLES_CHAIN" -m set --match-set "$set_name" src -j DROP
        fi
    else
        if [ "$family" = "inet" ]; then
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Adding nft rule for $set_name (IPv4)" >&2
            sudo nft add rule ip filter "$IPTABLES_CHAIN" ip saddr "@$set_name" drop 2>/dev/null
        else
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Adding nft rule for $set_name (IPv6)" >&2
            sudo nft add rule ip6 filter "$IPTABLES_CHAIN" ip6 saddr "@$set_name" drop 2>/dev/null
        fi
    fi
}

# Update blocklist (Modified: Added aggregate fallback prompt, dynamic ipset chunking, ipset error logging)
update_blocklist() {
    local dry_run="$1"
    check_sudo
    check_dependencies
    setup_config_dir
    [ ! -d "$CONFIG_DIR" ] || ! ls "$CONFIG_DIR"/*.conf >/dev/null 2>&1 && { echo "No configs in $CONFIG_DIR. Use --config"; exit 1; }

    : > "$IP_LIST"
    local total_cidr=0
    if [ -s "$IP_LIST" ]; then
        total_cidr=$(wc -l < "$IP_LIST")
        if [ "$total_cidr" -gt 100000 ]; then
            echo "Warning: $total_cidr CIDRs detected across all blocklists; processing may take significant time."
            if [ "$NON_INTERACTIVE" -eq 0 ]; then
                read -p "Continue? (y/N): " continue_large
                [[ ! "$continue_large" =~ ^[Yy]$ ]] && { echo "Aborted"; exit 0; }
            fi
        fi
    fi
    for conf_file in "$CONFIG_DIR"/*.conf; do
        if [ -f "$conf_file" ]; then
            echo "Processing $conf_file... (at $(date))"
            if process_blocklist "$conf_file"; then
                local cidrs=$(grep -c '^inet' "$IP_LIST")
                [ "$IPV6_ENABLED" -eq 1 ] && cidrs=$((cidrs + $(grep -c '^inet6' "$IP_LIST")))
                total_cidr=$((total_cidr + cidrs))
            fi
        fi
    done

    [ ! -s "$IP_LIST" ] && { echo "No valid CIDRs retrieved"; exit 1; }

    echo "First 5 lines of merged list:"
    head -n 5 "$IP_LIST"
    echo "Total valid CIDRs: $total_cidr"
    echo "Duplicate CIDRs:"
    local dupes=$(LC_ALL=C sort "$IP_LIST" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | uniq -d | wc -l)
    echo "$dupes"
    echo "------------------------"

    [ "$dry_run" -eq 1 ] && { echo "Dry run: Would apply $((total_cidr - dupes)) entries"; return 0; }

    # Aggregate CIDRs
    AGGREGATED_CIDR_LIST=$(mktemp /tmp/aggregated_cidr_list.XXXXXX) || { echo "Error: Failed to create temp file"; exit 1; }
    AGGREGATED_CIDR_LIST_V6=$(mktemp /tmp/aggregated_cidr_list_v6.XXXXXX) || { echo "Error: Failed to create temp file"; exit 1; }
    chmod 600 "$AGGREGATED_CIDR_LIST" "$AGGREGATED_CIDR_LIST_V6"

    # Check for large CIDR counts without aggregate in interactive mode
    if [ "$NO_IPV4_MERGE" != "y" ] && ! command -v aggregate >/dev/null && [ -s "$IP_LIST" ]; then
        num_ipv4=$(grep -c '^inet' "$IP_LIST")
        if [ "$num_ipv4" -gt 10000 ]; then
            if [ "$NON_INTERACTIVE" -eq 0 ]; then
                echo "Warning: 'aggregate' not found and $num_ipv4 IPv4 CIDRs detected; Bash merging may be slow"
                read -p "Skip IPv4 merging to avoid delays (risks overlaps)? (y/N): " skip_merge
                [[ "$skip_merge" =~ ^[Yy]$ ]] && NO_IPV4_MERGE=1
            elif [ "$NON_INTERACTIVE_SKIP_MERGE" = "y" ]; then
                NO_IPV4_MERGE=1
            fi
        fi
    fi
    if [ "$NO_IPV6_MERGE" != "y" ] && ! command -v aggregate6 >/dev/null && [ -s "$IP_LIST" ]; then
        num_ipv6=$(grep -c '^inet6' "$IP_LIST")
        if [ "$num_ipv6" -gt 10000 ]; then
            if [ "$NON_INTERACTIVE" -eq 0 ]; then
                echo "Warning: 'aggregate6' not found and $num_ipv6 IPv6 CIDRs detected; Bash merging may be slow"
                read -p "Skip IPv6 merging to avoid delays (risks overlaps)? (y/N): " skip_merge_v6
                [[ "$skip_merge_v6" =~ ^[Yy]$ ]] && NO_IPV6_MERGE=1
            elif [ "$NON_INTERACTIVE_SKIP_MERGE" = "y" ]; then
                NO_IPV6_MERGE=1
            fi
        fi
    fi

    # IPv4 aggregation
    if [ "$NO_IPV4_MERGE" = "y" ]; then
        grep '^inet' "$IP_LIST" | cut -d' ' -f2 > "$AGGREGATED_CIDR_LIST"
    elif command -v aggregate >/dev/null && [ -s "$IP_LIST" ]; then
        grep '^inet' "$IP_LIST" | cut -d' ' -f2 | aggregate -q > "$AGGREGATED_CIDR_LIST"
    else
        grep '^inet' "$IP_LIST" | cut -d' ' -f2 > "$AGGREGATED_CIDR_LIST"
        merge_cidrs_bash "$AGGREGATED_CIDR_LIST" "$AGGREGATED_CIDR_LIST.tmp"
        mv "$AGGREGATED_CIDR_LIST.tmp" "$AGGREGATED_CIDR_LIST"
    fi

    # IPv6 aggregation
    if [ "$IPV6_ENABLED" -eq 1 ]; then
        if [ "$NO_IPV6_MERGE" = "y" ]; then
            grep '^inet6' "$IP_LIST" | cut -d' ' -f2 > "$AGGREGATED_CIDR_LIST_V6"
        elif command -v aggregate6 >/dev/null && [ -s "$IP_LIST" ]; then
            grep '^inet6' "$IP_LIST" | cut -d' ' -f2 | aggregate6 -q > "$AGGREGATED_CIDR_LIST_V6"
        else
            grep '^inet6' "$IP_LIST" | cut -d' ' -f2 > "$AGGREGATED_CIDR_LIST_V6"
            merge_cidrs_bash_ipv6 "$AGGREGATED_CIDR_LIST_V6" "$AGGREGATED_CIDR_LIST_V6.tmp"
            mv "$AGGREGATED_CIDR_LIST_V6.tmp" "$AGGREGATED_CIDR_LIST_V6"
        fi
    else
        : > "$AGGREGATED_CIDR_LIST_V6"
    fi

    # Calculate total unique CIDRs after aggregation
    num_ipv4_cidrs=$(wc -l < "$AGGREGATED_CIDR_LIST")
    num_ipv6_cidrs=$(wc -l < "$AGGREGATED_CIDR_LIST_V6")
    num_cidrs=$((num_ipv4_cidrs + num_ipv6_cidrs))
    echo "Total unique CIDRs: $num_cidrs" >&2

    # Apply CIDRs to ipsets
    if [ -s "$AGGREGATED_CIDR_LIST" ]; then
        echo "Applying $num_ipv4_cidrs IPv4 CIDRs to $IPSET_NAME"
        apply_ipset inet "$IPSET_NAME" "$AGGREGATED_CIDR_LIST" "$num_ipv4_cidrs"
    else
        echo "No IPv4 CIDRs to apply"
        num_ipv4_cidrs=0
    fi
    if [ "$IPV6_ENABLED" -eq 1 ] && [ -s "$AGGREGATED_CIDR_LIST_V6" ]; then
        echo "Applying $num_ipv6_cidrs IPv6 CIDRs to ${IPSET_NAME}_v6"
        apply_ipset inet6 "${IPSET_NAME}_v6" "$AGGREGATED_CIDR_LIST_V6" "$num_ipv6_cidrs"
    else
        [ "$IPV6_ENABLED" -eq 1 ] && echo "No IPv6 CIDRs to apply"
        num_ipv6_cidrs=0
    fi

    # Function to apply CIDRs to ipset or nftables set
    apply_ipset() {
        local family="$1" set_name="$2" ipset_file="$3" expected_count="$4"
        local tmp_script
        tmp_script=$(mktemp /tmp/ipset_commands.XXXXXX) || { echo "Error: Failed to create temp file"; exit 1; }
        chmod 600 "$tmp_script"

        if [ "$DRY_RUN" -eq 1 ]; then
            echo "Dry run: Would apply $set_name from $ipset_file ($expected_count entries)"
            rm -f "$tmp_script"
            return 0
        fi

        check_sudo

        if [ "$FIREWALL_BACKEND" = "iptables" ]; then
            # Check if ipset exists and is non-empty
            if sudo ipset list "$set_name" >/dev/null 2>&1 && [ "$(sudo ipset list "$set_name" | grep -c 'Number of entries')" -gt 0 ]; then
                echo "Reusing existing ipset $set_name"
                # Reapply rule if missing
                if ! sudo iptables -C "$IPTABLES_CHAIN" -m set --match-set "$set_name" src -j DROP 2>/dev/null; then
                    sudo iptables -I "$IPTABLES_CHAIN" -m set --match-set "$set_name" src -j DROP
                    echo "Reapplied firewall rule for $set_name"
                fi
                [ "$family" = "inet6" ] && ! sudo ip6tables -C "$IPTABLES_CHAIN" -m set --match-set "$set_name" src -j DROP 2>/dev/null && sudo ip6tables -I "$IPTABLES_CHAIN" -m set --match-set "$set_name" src -j DROP
                rm -f "$tmp_script"
                return 0
            fi

            # Calculate hashsize and maxelem
            local hashsize maxelem
            hashsize=$(awk -v n="$expected_count" 'BEGIN { n = n * 1.5; logval = log(n)/log(2); print 2^int(logval+1) }')
            maxelem=$((expected_count * 2))
            [ $hashsize -lt 1024 ] && hashsize=1024
            [ $maxelem -lt 1024 ] && maxelem=1024
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Calculated hashsize=$hashsize, maxelem=$maxelem for $set_name" >&2

            # Create new ipset
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Creating ipset $set_name with hashsize $hashsize" >&2
            sudo ipset create "$set_name" hash:net hashsize "$hashsize" family "$family" maxelem "$maxelem" 2>/dev/null || {
                echo "Error: Failed to create ipset $set_name"
                rm -f "$tmp_script"
                exit 1
            }

            # Populate ipset
            echo "flush $set_name" > "$tmp_script"
            local cidr_count=0
            if command -v pv >/dev/null; then
                pv -f -N "Applying $family CIDRs to $set_name" -s "$expected_count" "$ipset_file" | while IFS= read -r cidr; do
                    [ -z "$cidr" ] && continue
                    if [ "$IPSET_TEST" -eq 1 ] && sudo ipset test "$set_name" "$cidr" 2>/dev/null; then
                        [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Skipping duplicate $family CIDR $cidr in $set_name" >&2
                    else
                        echo "add $set_name $cidr" >> "$tmp_script"
                    fi
                    ((cidr_count++))
                done
            else
                while IFS= read -r cidr; do
                    [ -z "$cidr" ] && continue
                    if [ "$IPSET_TEST" -eq 1 ] && sudo ipset test "$set_name" "$cidr" 2>/dev/null; then
                        [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Skipping duplicate $family CIDR $cidr in $set_name" >&2
                    else
                        echo "add $set_name $cidr" >> "$tmp_script"
                    fi
                    ((cidr_count++))
                done < "$ipset_file"
            fi

            # Apply ipset commands with chunking fallback
            local ipset_output ipset_status chunk_size=100000 attempts=0 max_attempts=3
            ipset_output=$(sudo ipset restore < "$tmp_script" 2>&1)
            ipset_status=$?
            while [ $ipset_status -ne 0 ] && [ $attempts -lt $max_attempts ]; do
                echo "Failed to apply ipset $set_name: $ipset_output" | tee -a "$LOG_FILE"
                echo "Attempting fallback with chunk size $chunk_size..." | tee -a "$LOG_FILE"
                split -l "$chunk_size" "$tmp_script" ipset_chunk_
                sudo ipset destroy "$set_name" 2>/dev/null
                sudo ipset create "$set_name" hash:net hashsize "$hashsize" family "$family" maxelem "$maxelem" 2>/dev/null
                for chunk in ipset_chunk_*; do
                    ipset_output=$(sudo ipset restore < "$chunk" 2>&1)
                    ipset_status=$?
                    if [ $ipset_status -ne 0 ]; then
                        echo "Failed to apply chunk $chunk: $ipset_output" | tee -a "$LOG_FILE"
                        break
                    fi
                done
                rm -f ipset_chunk_*
                attempts=$((attempts + 1))
                chunk_size=$((chunk_size / 2))
                [ $chunk_size -lt 1000 ] && chunk_size=1000
            done
            if [ $ipset_status -ne 0 ]; then
                echo "Failed to apply ipset $set_name after $max_attempts attempts" | tee -a "$LOG_FILE"
                if [ -s "$IPSET_BACKUP_FILE" ]; then
                    if sudo ipset restore < "$IPSET_BACKUP_FILE" 2>/dev/null; then
                        echo "Restored previous state"
                        apply_rule "$family" "$set_name"
                    else
                        echo "Failed to restore backup" | tee -a "$LOG_FILE"
                    fi
                fi
                rm -f "$tmp_script"
                exit 1
            fi
            echo "Applied $cidr_count entries to $set_name"
        else
            # Nftables
            if sudo nft list set ip filter "$set_name" >/dev/null 2>&1 || sudo nft list set ip6 filter "$set_name" >/dev/null 2>&1; then
                echo "Reusing existing nftables set $set_name"
                if ! sudo nft list chain ip filter "$IPTABLES_CHAIN" | grep -q "set $set_name"; then
                    sudo nft add rule ip filter "$IPTABLES_CHAIN" ip saddr "@$set_name" drop
                    echo "Reapplied firewall rule for $set_name (IPv4)"
                fi
                [ "$family" = "inet6" ] && ! sudo nft list chain ip6 filter "$IPTABLES_CHAIN" | grep -q "set $set_name" && sudo nft add rule ip6 filter "$IPTABLES_CHAIN" ip6 saddr "@$set_name" drop && echo "Reapplied firewall rule for $set_name (IPv6)"
                rm -f "$tmp_script"
                return 0
            fi

            # Create new nftables set
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Creating nftables set $set_name" >&2
            if [ "$family" = "inet" ]; then
                sudo nft add set ip filter "$set_name" "{ type ipv4_addr; flags interval; }" 2>/dev/null
            else
                sudo nft add set ip6 filter "$set_name" "{ type ipv6_addr; flags interval; }" 2>/dev/null
            fi

            # Populate nftables set
            local cidr_count=0
            if command -v pv >/dev/null; then
                pv -f -N "Applying $family CIDRs to $set_name" -s "$expected_count" "$ipset_file" | while IFS= read -r cidr; do
                    [ -z "$cidr" ] && continue
                    sudo nft add element ip filter "$set_name" "{ $cidr }" 2>/dev/null || sudo nft add element ip6 filter "$set_name" "{ $cidr }" 2>/dev/null
                    ((cidr_count++))
                done
            else
                while IFS= read -r cidr; do
                    [ -z "$cidr" ] && continue
                    sudo nft add element ip filter "$set_name" "{ $cidr }" 2>/dev/null || sudo nft add element ip6 filter "$set_name" "{ $cidr }" 2>/dev/null
                    ((cidr_count++))
                done < "$ipset_file"
            fi
            echo "Applied $cidr_count entries to $set_name"
        fi
        rm -f "$tmp_script"
    }

    # Clean up temporary files
    rm -f "$IP_LIST" "$AGGREGATED_CIDR_LIST" "$AGGREGATED_CIDR_LIST_V6"

    # Backup ipset
    if [ "$DRY_RUN" -eq 0 ]; then
        backup_set "$IPSET_NAME"
        [ "$IPV6_ENABLED" -eq 1 ] && backup_set "${IPSET_NAME}_v6"
    fi

    # Verify entries
    local added=0
    if [ "$FIREWALL_BACKEND" = "iptables" ]; then
        [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Verifying ipset $IPSET_NAME entries" >&2
        added=$(sudo ipset list "$IPSET_NAME" | grep -c '[0-9]\.[0-9]')
        [ "$IPV6_ENABLED" -eq 1 ] && {
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Verifying ipset ${IPSET_NAME}_v6 entries" >&2
            added=$((added + $(sudo ipset list "${IPSET_NAME}_v6" | grep -c '[0-9a-fA-F:]')))
        }
    else
        [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Verifying nft set $IPSET_NAME entries" >&2
        added=$(sudo nft list set ip filter "$IPSET_NAME" | grep -c '[0-9]\.[0-9]')
        [ "$IPV6_ENABLED" -eq 1 ] && {
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Verifying nft set ${IPSET_NAME}_v6 entries" >&2
            added=$((added + $(sudo nft list set ip6 filter "${IPSET_NAME}_v6" | grep -c '[0-9a-fA-F:]')))
        }
    fi
    echo "Added $added entries"
    [ "$added" -lt $((num_cidrs / 2)) ] && echo "Warning: Fewer entries than expected"

    # Check for critical rules (e.g., SSH)
    local rule_pos=1
    if [ "$FIREWALL_BACKEND" = "iptables" ] && sudo iptables -L "$IPTABLES_CHAIN" -n | grep -q "ACCEPT.*tcp dpt:22"; then
        if [ "$NON_INTERACTIVE" -eq 1 ]; then
            [ "$NON_INTERACTIVE_CONTINUE_IPTABLES" = "y" ] && rule_pos=2
        else
            echo "Warning: Critical rule (e.g., SSH) detected"
            read -p "Insert rule anyway? (y/N): " continue_iptables
            [[ "$continue_iptables" =~ ^[Yy]$ ]] && rule_pos=2
        fi
    fi
}

# Main script (Modified: Added stale lock directory cleanup)
LOCK_DIR="/tmp/blocklist.lock.d"
# Clean up stale lock directory if it exists
if [ -d "$LOCK_DIR" ]; then
    echo "Warning: Stale lock directory $LOCK_DIR found; attempting to remove it"
    rmdir "$LOCK_DIR" 2>/dev/null || { echo "Error: Cannot remove stale lock directory $LOCK_DIR; another instance may be running"; exit 1; }
fi
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
    echo "Error: Another instance is running or lock directory creation failed"
    exit 1
fi

trap 'rmdir "$LOCK_DIR" 2>/dev/null; cleanup' EXIT INT TERM

# Initialize modes
load_config
setup_temp_files
DEBUG_MODE=0
VERBOSE_DEBUG=0
LOG_MODE=0
DRY_RUN=0
IPV6_ENABLED=0
NON_INTERACTIVE=0
IPSET_TEST=0
NO_IPV4_MERGE=0
NO_IPV6_MERGE=0
[ "$NO_IPV4_MERGE" = "y" ] && NO_IPV4_MERGE=1
[ "$NO_IPV6_MERGE" = "y" ] && NO_IPV6_MERGE=1
ACTIONS=()

# Parse options
while [ $# -gt 0 ]; do
    case "$1" in
        --help) ACTIONS+=("help");;
        --config) ACTIONS+=("config");;
        --auth) ACTIONS+=("auth");;
        --purge) ACTIONS+=("purge");;
        --clear-rules) ACTIONS+=("clear_rules");;
        --config-dir) shift; CONFIG_DIR_OVERRIDE="$1";;
        --config-dir=*) CONFIG_DIR_OVERRIDE="${1#*=}";;
        --apply-rules) ACTIONS+=("apply_rules");;
        --debug) DEBUG_MODE=1;;
        --verbosedebug) DEBUG_MODE=1; VERBOSE_DEBUG=1;;
        --log) LOG_MODE=1;;
        --dry-run) DRY_RUN=1;;
        --ipv6) IPV6_ENABLED=1;;
        --no-ipv4-merge) NO_IPV4_MERGE=1;;
        --no-ipv6-merge) NO_IPV6_MERGE=1;;
        --backend) shift; FIREWALL_BACKEND="$1";;
        --non-interactive) NON_INTERACTIVE=1;;
        --ipset-test) IPSET_TEST=1; echo "Warning: --ipset-test enabled. This may add ~5-10 seconds for 1,500 duplicates.";;
        *) echo "Unknown option: $1"; show_help; exit 1;;
    esac
    shift
done

# Check script syntax in debug mode
if [ "$DEBUG_MODE" -eq 1 ]; then
    if ! bash -n "$0" 2>/tmp/blocklist_syntax_errors.$$; then
        echo "Syntax errors detected in $0:"
        cat /tmp/blocklist_syntax_errors.$$
        rm -f /tmp/blocklist_syntax_errors.$$
        if [ "$NON_INTERACTIVE" -eq 0 ]; then
            read -p "Continue despite syntax errors? (y/N): " continue_syntax
            if [[ ! "$continue_syntax" =~ ^[Yy]$ ]]; then
                echo "Exiting due to syntax errors"
                exit 1
            fi
            echo "Proceeding with potential risks"
        else
            echo "Non-interactive mode: Exiting due to syntax errors"
            exit 1
        fi
    else
        echo "Syntax check passed"
        rm -f /tmp/blocklist_syntax_errors.$$
    fi
fi

# Debug: Confirm debug mode settings
[ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Debug modes - DEBUG_MODE=$DEBUG_MODE, VERBOSE_DEBUG=$VERBOSE_DEBUG" >&2

[ "$VERBOSE_DEBUG" -eq 1 ] && set -x
if [ "$LOG_MODE" -eq 1 ]; then
    touch "$LOG_FILE" 2>/dev/null || { echo "Error: Cannot write to $LOG_FILE"; exit 1; }
    chmod 600 "$LOG_FILE"
    [ -f "$LOG_FILE" ] && cp -f "$LOG_FILE" "${LOG_FILE}.bak"
    if [ ! -t 1 ]; then  # Check if stdout is NOT a terminal (i.e., redirected)
        echo "Warning: Output is already redirected (e.g., to a file); also logging to $LOG_FILE. Ctrl+C to cancel if undesired."
    fi
    exec > >(tee -a "$LOG_FILE") 2>&1
    echo "Logging to $LOG_FILE"
fi

[ -n "$CRON" ] && { sudo -n true || { echo "Cron error: Sudo requires password"; exit 1; }; }

[ ${#ACTIONS[@]} -eq 0 ] && ACTIONS+=("update")

# Display start time
echo "Script started at: $(date)"

for action in "${ACTIONS[@]}"; do
    case "$action" in
        help) show_help;;
        config) manage_configs;;
        auth) manage_credentials;;
        purge) purge_blocklist;;
        clear_rules) clear_rules;;
        apply_rules|update) load_credentials; update_blocklist "$DRY_RUN";;
    esac
done

# Display completion time and script run time
END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))
ELAPSED_MIN=$((ELAPSED / 60))
ELAPSED_SEC=$((ELAPSED % 60))
echo "Script completed at: $(date) (Elapsed: ${ELAPSED_MIN}m ${ELAPSED_SEC}s)"
