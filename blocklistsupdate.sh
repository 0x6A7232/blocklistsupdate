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

# Most current version as of this edit: 4.6.5

# Supports iptables/nftables, IPv4/IPv6, multiple blocklist sources, and configurable settings
# Version 4.6.5: Added --status option to display current ipset/nftables sets, iptables/ip6tables/nftables rules, and count of blocked IPs with sample entries; improved user feedback for monitoring firewall state; fixed redundant mv error in IPv4 and IPv6 aggregation blocks to ensure robust file handling with single or multiple blocklists.

# Inspired from https://lowendspirit.com/discussion/7699/use-a-blacklist-of-bad-ips-on-your-linux-firewall-tutorial
# Credit to user itsdeadjim ( https://lowendspirit.com/profile/itsdeadjim )
# The original version of the script by itsdeadjim is referred to as 0.5 if it is uploaded

# Load configuration file, generating it if it doesn't exist
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
    if [ ! -f "$CONFIG_FILE" ] || [ ! -r "$CONFIG_FILE" ]; then
        # Generate default config with comments
        if ! touch "$CONFIG_FILE" 2>/dev/null; then
            echo "Error: Cannot write to $CONFIG_FILE" >&2
            exit 1
        fi
        cat > "$CONFIG_FILE" << 'EOF'
# Blocklist script configuration file
# Note: If using --config-dir, paths below are relative to that directory
# For example, if --config-dir=/home/user, CONFIG_DIR becomes /home/user/.blocklists
# To use absolute paths, edit these settings after the file is created
# To use the defaults without --config-dir, leave as-is
# Paths are relative to $HOME unless --config-dir is specified
# Edit these settings to customize paths, names, and behaviors

# Directory for blocklist configuration files
CONFIG_DIR=$DEFAULT_CONFIG_DIR

# Path to credentials file
CRED_FILE=$ORIGINAL_HOME/.blocklistcredentials.conf

# Path to log file (used with --log)
LOG_FILE=$ORIGINAL_HOME/blocklistsupdate.log

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
        source "$CONFIG_FILE" || { echo "Error: Failed to source $CONFIG_FILE" >&2; exit 1; }
    else
        echo "Error: Cannot read $CONFIG_FILE" >&2
        exit 1
    fi
}

# Determine script directory and set HELP_FILE location
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HELP_FILE="$SCRIPT_DIR/blocklist_readme.md"

# Check if script directory is writable; if not, fall back to user's home directory
if [ ! -w "$SCRIPT_DIR" ]; then
    HELP_FILE="$ORIGINAL_HOME/blocklist_readme.md"
    echo "Warning: Script directory ($SCRIPT_DIR) is not writable; placing help file in $HELP_FILE" >&2
fi

update_configfile() {
    # Check for the existence of a backup config file
    local backup_file="$CONFIG_FILE.bak"
    if [ -f "$backup_file" ]; then
        echo "INFO: config.conf.bak found in $(dirname "$backup_file")/" >&2
    else
        echo "INFO: No backup config file found in $(dirname "$backup_file")/" >&2
    fi

    # Present the menu
    echo "What do you want to do:" >&2
    echo "(U|u) Update the config file, backing up the old version (WARNING: any previous backups will be overridden!)" >&2
    echo "(C|c) View Current config file" >&2
    echo "(O|o) View Old config file backup" >&2
    echo "(Press any other key to exit)" >&2

    # Read user choice
    local choice
    if [ "$NON_INTERACTIVE" -eq 1 ]; then
        echo "Non-interactive mode: exiting as no action can be taken without user input" >&2
        return 0
    fi
    read -p "Your choice (U/C/O): " choice </dev/tty

    # Handle user choice
    case "$choice" in
        U|u)
            if [ ! -f "$CONFIG_FILE" ]; then
                echo "Error: Config file $CONFIG_FILE does not exist" >&2
                exit 1
            fi
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Backing up $CONFIG_FILE to $backup_file" >&2
            cp -f "$CONFIG_FILE" "$backup_file" || {
                echo "Error: Failed to create backup of $CONFIG_FILE to $backup_file" >&2
                exit 1
            }
            chmod 600 "$backup_file" 2>/dev/null
            echo "Backup of config file created at $backup_file" >&2
            if [ -f "$backup_file" ]; then
                rm -f "$CONFIG_FILE" || {
                    echo "Error: Failed to delete $CONFIG_FILE after backup" >&2
                    exit 1
                }
            fi
            echo "INFO: Re-launch the script to generate the new config file" >&2
            echo "You can compare the backup ($backup_file) with the new config to merge your changes" >&2
            ;;
        C|c)
            if [ ! -f "$CONFIG_FILE" ]; then
                echo "Error: Config file $CONFIG_FILE does not exist" >&2
                exit 1
            fi
            echo "Current config file ($CONFIG_FILE):" >&2
            cat "$CONFIG_FILE" >&2
            ;;
        O|o)
            if [ ! -f "$backup_file" ]; then
                echo "Error: Backup config file $backup_file does not exist" >&2
                exit 1
            fi
            echo "Old config file backup ($backup_file):" >&2
            cat "$backup_file" >&2
            ;;
        *)
            echo "Exiting" >&2
            return 0
            ;;
    esac
}

update_readme() {
    local readme_file="$HELP_FILE"
    if ! touch "$readme_file" 2>/dev/null; then
        echo "Error: Cannot write to $readme_file" >&2
        exit 1
    fi
    cat > "$readme_file" << 'EOF'
# Blocklist Update Script (v4.6.4)
Manages IPv4/IPv6 blocklists for Linux firewalls using iptables/ipset or nftables.

## Features
- Downloads and merges blocklists from multiple sources with validation and deduplication.
- Supports iptables/ipset and nftables backends for flexible firewall integration.
- Configurable via ~/.blocklist.conf and per-source ~/.blocklists/*.conf.
- Fast rule toggling with --clear-rules and --apply-rules (reuses ipsets for instant application).
- Credential management for authenticated blocklists (--auth).
- Progress bars with pv, syntax checks, and detailed debugging (--debug, --verbosedebug).
- Non-interactive mode and cron support for automation.
- Robust IPv4/IPv6 CIDR merging, with optional aggregate/aggregate6 for speed.
- Complete purge of rules, ipsets, configs, and credentials (--purge-all).
- README updating for version consistency (--update-readme).

## Installation
On a Debian-based system, install dependencies and prepare the script:

sudo apt-get install wget gunzip awk iptables ipset
# Optional for progress bars and faster merging
sudo apt-get install pv aggregate aggregate6
# Enable script execution with:
chmod +x blocklistsupdate.sh

Notes:
- Replace iptables ipset with nftables if using --backend nftables.
- pv enables progress bars; aggregate/aggregate6 speed up merging for large blocklists (>10,000 CIDRs).
- Place the script (or create a symlink with ln -s TARGET LINK_NAME) in /usr/local/bin/ for system-wide access (optional).

## Usage
1. Configure blocklist sources:
./blocklistsupdate.sh --config
2. Update and apply blocklists:
./blocklistsupdate.sh
3. Toggle rules without rebuilding ipsets:
./blocklistsupdate.sh --clear-rules
./blocklistsupdate.sh --apply-rules
4. Purge all data (add -y to purge immediately without prompting):
./blocklistsupdate.sh --purge-all
5. Check current blocklist status (sets, rules, and entry counts):
./blocklistsupdate.sh --status
   - Shows up to 5 sample IPs/CIDRs per set, total entries, and firewall backend.
6. Update README:
./blocklistsupdate.sh --update-readme
7. View full options:
./blocklistsupdate.sh --help

## Configuration
- Edit ~/.blocklist.conf for defaults (e.g., CONFIG_DIR, IPSET_NAME).
- Add blocklist sources in ~/.blocklists/*.conf with URL and (if needed) USERNAME, PIN.
- Use --auth to manage credentials for authenticated sources.
- Log file: ~/blocklistsupdate.log (or custom with --config-dir).
EOF
    if [ $? -eq 0 ]; then
        echo "README updated at $readme_file" >&2
        chmod 600 "$readme_file" 2>/dev/null
    else
        echo "Error: Failed to write README to $readme_file" >&2
        exit 1
    fi
}

# Generate blocklist_readme.md if it doesn't exist
if [ ! -f "$HELP_FILE" ]; then
    # Generate help file
    if ! touch "$HELP_FILE" 2>/dev/null; then
        echo "Error: Cannot write to $HELP_FILE" >&2
        exit 1
    fi
    echo "Help file not found; creating $HELP_FILE" >&2
    update_readme
fi

# Capture and display start time for runtime calculation and user reference
START_TIME=$(date +%s)
START_TIME_READABLE=$(date)
echo "Script started at: $START_TIME_READABLE" >&2

# Create secure temporary files
setup_temp_files() {
    TEMP_DIR=$(mktemp -d "$CONFIG_DIR/tmp.XXXXXX") || { echo "Error: Failed to create temp directory" >&2; exit 1; }
    chmod 700 "$TEMP_DIR"
    [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Using temporary directory $TEMP_DIR" >&2
    if ! [ -w "$TEMP_DIR" ]; then
        echo "Error: $TEMP_DIR is not writable" >&2
        exit 1
    fi
    IP_LIST_RAW="$TEMP_DIR/iplist_raw"
    IP_LIST="$TEMP_DIR/iplist"
    IPSET_BACKUP_FILE="$TEMP_DIR/ipset_backup"
    touch "$IP_LIST_RAW" "$IP_LIST" "$IPSET_BACKUP_FILE" || { echo "Error: Failed to create temp files" >&2; exit 1; }
    chmod 660 "$IP_LIST_RAW" "$IP_LIST" "$IPSET_BACKUP_FILE"
}

# Cleanup temporary files and lock directory on exit
cleanup() {
    rm -rf "$TEMP_DIR"
    [ "$DEBUG_MODE" -eq 1 ] && echo "Script exited at: $(date)" >&2
    if [ -n "$LOCK_DIR" ] && [ -d "$LOCK_DIR" ]; then
        rm -f "$LOCK_DIR/pid" 2>/dev/null
        if ! rmdir "$LOCK_DIR" 2>/dev/null; then
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Failed to remove lock directory $LOCK_DIR; contents:" >&2
            [ "$DEBUG_MODE" -eq 1 ] && ls -l "$LOCK_DIR" >&2
            rm -rf "$LOCK_DIR" 2>/dev/null
        fi
        [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Removed lock directory $LOCK_DIR" >&2
    fi
}

# Display usage information
show_help() {
    echo "Blocklist management script for Linux firewalls (iptables/nftables, IPv4/IPv6)"
    echo "Usage: $0 [--debug-level=1|2] [--log] [--dry-run] [--no-ipv4-merge] [--no-ipv6-merge] [--non-interactive]"
    echo "Options:"
    echo "  --help            Display this help message"
    echo "  --config          Manage blocklist config files (add, edit, delete, view)"
    echo "  --auth            Edit or clear credentials"
    echo "  --config-dir=/path  Override default config directory (~/.blocklists)"
    echo "  --purge           Remove blocklist rules and ipsets; optionally delete configs"
    echo "  --purge-all [-y]  Remove all rules, ipsets, configs, and credentials (use -y to skip prompt)"
    echo "  --clear-rules     Remove blocklist rules, keeping ipsets (re-enable with --apply-rules)"
    echo "  --apply-rules     Re-apply blocklist rules from configs"
    echo "  --update-readme   Update the README file to the version included with this script"
    echo "  --update-configfile  Update the config file (backing up current) or view current or backup config file"
    echo "  --debug-level=1, --debug  Enable basic debug output (includes syntax check)"
    echo "  --debug-level=2, --verbosedebug  Enable verbose debug (adds script tracing to basic debug)"
    echo "  --log             Log output to $LOG_FILE"
    echo "  --dry-run         Simulate blocklist update without making changes"
    echo "  --ipv6            Process IPv6 addresses (default: IPv4 only)"
    echo "  --no-ipv4-merge   Skip IPv4 CIDR merging"
    echo "  --no-ipv6-merge   Skip IPv6 CIDR merging"
    echo "  --backend=iptables|nftables  Set firewall backend (default: $FIREWALL_BACKEND)"
    echo "  --non-interactive  Run without user prompts, using config defaults"
    echo "  --ipset-test      Check for duplicates in ipset (adds ~5-10 seconds for 1,500 duplicates)"
    echo "  --status          Display current ipset/nftables sets and iptables/nftables rules with entry counts"
    echo "Requirements:"
    echo "  - Required: wget, gunzip, awk, and either (iptables and ipset) or nftables"
    echo "  - Recommended: pv (progress bars), aggregate/aggregate6 (faster merging)"
    echo "Notes:"
    echo "  - Configs stored in $CONFIG_DIR/*.conf"
    echo "  - Log file: ~/blocklistsupdate.log (or custom with --config-dir)"
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
        echo "Error: 'sudo' command not found" >&2
        exit 1
    fi
    for cmd in $cmds; do
        if ! command -v "$cmd" >/dev/null; then
            echo "Error: Required command '$cmd' not found. The script may not function without it." >&2
            exit 1
        fi
    done
    # Optional tools
    for cmd in unzip 7z aggregate aggregate6 pv; do
        if ! command -v "$cmd" >/dev/null; then
            if [ "$cmd" = "pv" ]; then
                echo "Warning: 'pv' not found; progress bars for downloads, parsing, and CIDR application will not be displayed" >&2
            elif [ "$cmd" = "aggregate" ]; then
                echo "Warning: 'aggregate' not found; falling back to slower Bash-based IPv4 CIDR merging. Use --no-ipv4-merge to skip." >&2
            elif [ "$cmd" = "aggregate6" ]; then
                echo "Warning: 'aggregate6' not found; falling back to slower Bash-based IPv6 CIDR merging. Use --no-ipv6-merge to skip." >&2
            else
                echo "Warning: '$cmd' not found; some features may be limited" >&2
            fi
        fi
    done
    # Kernel module check for ipset
    if [ "$FIREWALL_BACKEND" = "iptables" ]; then
        [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Checking ipset kernel module" >&2
        if ! sudo modprobe ip_set >/dev/null 2>&1; then
            echo "Error: Failed to load ipset kernel module (ip_set). Ensure it is installed and available." >&2
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: modprobe ip_set output: $(sudo modprobe ip_set 2>&1)" >&2
            exit 1
        fi
        if ! lsmod | grep -q ip_set; then
            echo "Error: ipset kernel module (ip_set) not loaded. Ensure it is installed and available." >&2
            exit 1
        fi
        [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: ipset kernel module (ip_set) is loaded" >&2
    fi
}

# Verify sudo access, offering re-launch if sudo isn't passwordless
check_sudo() {
    if [ "$EUID" -eq 0 ]; then
        # Allow overriding config directory (e.g., for sudo runs)
        [ -z "$CONFIG_DIR_OVERRIDE" ] && CONFIG_DIR_OVERRIDE="$ORIGINAL_HOME"
        # Already running as root (sudo)
        return 0
    fi
    # Check if sudo is available without prompting
    if sudo -n true 2>/dev/null; then
        return 0
    fi
    # Interactive mode: Offer choice to re-launch or prompt as needed
    if [ "$NON_INTERACTIVE" -eq 0 ] && [ -z "$CRON" ]; then
        echo "This script requires sudo access." >&2
        read -p "Enter password as needed (p) or re-launch using sudo for uninterrupted runs (R or Enter)?: " choice </dev/tty
        [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: User chose sudo path: ${choice:-R}" >&2
        if [[ "$choice" =~ ^[Rr]$ || -z "$choice" ]]; then
            echo "Re-launching with sudo..." >&2
            # Preserve original arguments
            exec sudo "$0" --config-dir="$HOME" "${ORIGINAL_ARGS[@]}"
        else
            echo "Will prompt for sudo password when needed." >&2
            if sudo true; then
                return 0
            else
                echo "Error: Sudo authentication failed" >&2
                exit 1
            fi
        fi
    else
        echo "Error: Sudo access required (non-interactive mode requires passwordless sudo)" >&2
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
        echo "Warning: $CONFIG_DIR is not writable" >&2
    fi
    for conf_file in "$CONFIG_DIR"/*.conf; do
        if [ -f "$conf_file" ] && ! grep -q '^URL=' "$conf_file"; then
            echo "Warning: $conf_file missing URL; it will be skipped" >&2
        fi
    done
}

# Manage credentials
manage_credentials() {
    if [ "$NON_INTERACTIVE" -eq 1 ]; then
        if [ "$NON_INTERACTIVE_EDIT_CREDENTIALS" != "y" ]; then
            echo "Skipping credential edit in non-interactive mode" >&2
            return
        fi
    fi
    echo "Current credentials ($CRED_FILE):" >&2
    if [ -f "$CRED_FILE" ] && [ -r "$CRED_FILE" ]; then
        cat "$CRED_FILE"
    else
        echo "(None)" >&2
    fi
    echo
    if [ "$NON_INTERACTIVE" -eq 1 ]; then
        return
    fi
    read -p "Edit credentials? (y/N): " edit </dev/tty
    if [[ "$edit" =~ ^[Yy]$ ]]; then
        read -p "Enter username (blank for none): " username </dev/tty
        read -p "Enter PIN (blank for none): " pin </dev/tty
        if [ -z "$username" ] && [ -z "$pin" ]; then
            if [ -f "$CRED_FILE" ]; then
                [ -w "$CRED_FILE" ] && rm "$CRED_FILE" || sudo rm "$CRED_FILE"
                echo "Credentials cleared" >&2
            fi
        else
            if ! touch "$CRED_FILE" 2>/dev/null; then
                echo "Error: Cannot write to $CRED_FILE" >&2
                exit 1
            fi
            echo "USERNAME=$username" > "$CRED_FILE"
            echo "PIN=$pin" >> "$CRED_FILE"
            chmod 600 "$CRED_FILE"
            echo "Credentials updated" >&2
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
    echo "Current configs in $CONFIG_DIR:" >&2
    ls -1 "$CONFIG_DIR" | grep '\.conf$' | sed 's/\.conf$//' >&2 || echo "(None)" >&2
    echo
    echo "Options: (a)dd, (e)dit, (v)iew, (d)elete one, (D)elete all, (q)uit" >&2
    read -p "Choose action: " action </dev/tty
    case "$action" in
        a|A)
            read -p "Enter config name: " name </dev/tty
            name=$(sanitize_conf_name "$name")
            [ -z "$name" ] && { echo "Name required" >&2; exit 1; }
            read -p "Enter blocklist URL: " url </dev/tty
            [ -z "$url" ] && { echo "URL required" >&2; exit 1; }
            local clean_url stripped_user stripped_pin
            read clean_url stripped_user stripped_pin < <(sanitize_url "$url" | tr '|' ' ')
            local list_user list_pin
            if [ -n "$stripped_user" ] || [ -n "$stripped_pin" ]; then
                echo "Found credentials in URL:" >&2
                echo "Username: $stripped_user" >&2
                echo "PIN: $stripped_pin" >&2
                read -p "Add to config? (y/N): " auto_add </dev/tty
                if [[ "$auto_add" =~ ^[Yy]$ ]]; then
                    list_user="$stripped_user"
                    list_pin="$stripped_pin"
                fi
            fi
            [ -z "$list_user" ] && read -p "Enter username (blank for $CRED_FILE): " list_user </dev/tty
            [ -z "$list_pin" ] && read -p "Enter PIN (blank for $CRED_FILE): " list_pin </dev/tty
            conf_file="$CONFIG_DIR/$name.conf"
            echo "Writing URL to $conf_file" >&2
            echo "URL=$clean_url" > "$conf_file"
            [ -n "$list_user" ] && { echo "Writing USERNAME to $conf_file" >&2; echo "USERNAME=$list_user" >> "$conf_file"; }
            [ -n "$list_pin" ] && { echo "Writing PIN to $conf_file" >&2; echo "PIN=$list_pin" >> "$conf_file"; }
            chmod 600 "$conf_file"
            echo "Added $conf_file" >&2
            ;;
        e|E)
            read -p "Enter config name: " name </dev/tty
            name=$(sanitize_conf_name "$name")
            conf_file="$CONFIG_DIR/$name.conf"
            [ ! -f "$conf_file" ] && { echo "Config not found" >&2; exit 1; }
            echo "Current config ($conf_file):" >&2
            [ -r "$conf_file" ] && cat "$conf_file" >&2 || echo "(Permission denied)" >&2
            read -p "Enter new URL (blank to keep): " url </dev/tty
            local clean_url stripped_user stripped_pin
            if [ -n "$url" ]; then
                read clean_url stripped_user stripped_pin < <(sanitize_url "$url" | tr '|' ' ')
                if [ -n "$stripped_user" ] || [ -n "$stripped_pin" ]; then
                    echo "Found credentials in URL:" >&2
                    echo "Username: $stripped_user" >&2
                    echo "PIN: $stripped_pin" >&2
                    read -p "Add to config? (y/N): " auto_add </dev/tty
                    if [[ "$auto_add" =~ ^[Yy]$ ]]; then
                        list_user="$stripped_user"
                        list_pin="$stripped_pin"
                    fi
                fi
            fi
            [ -z "$list_user" ] && read -p "Enter new username (blank to keep): " list_user </dev/tty
            [ -z "$list_pin" ] && read -p "Enter new PIN (blank to keep): " list_pin </dev/tty
            if [ -n "$url" ]; then
                echo "Writing URL to $conf_file.tmp" >&2
                echo "URL=$clean_url" > "$conf_file.tmp"
            else
                grep '^URL=' "$conf_file" > "$conf_file.tmp"
            fi
            if [ -n "$list_user" ]; then
                echo "Writing USERNAME to $conf_file.tmp" >&2
                echo "USERNAME=$list_user" >> "$conf_file.tmp"
            elif grep '^USERNAME=' "$conf_file"; then
                grep '^USERNAME=' "$conf_file" >> "$conf_file.tmp"
            fi
            if [ -n "$list_pin" ]; then
                echo "Writing PIN to $conf_file.tmp" >&2
                echo "PIN=$list_pin" >> "$conf_file.tmp"
            elif grep '^PIN=' "$conf_file"; then
                grep '^PIN=' "$conf_file" >> "$conf_file.tmp"
            fi
            mv "$conf_file.tmp" "$conf_file"
            chmod 600 "$conf_file"
            echo "Updated $conf_file" >&2
            ;;
        v|V)
            read -p "Enter config name: " name </dev/tty
            name=$(sanitize_conf_name "$name")
            conf_file="$CONFIG_DIR/$name.conf"
            [ ! -f "$conf_file" ] && { echo "Config not found" >&2; exit 1; }
            echo "Config ($conf_file):" >&2
            [ -r "$conf_file" ] && cat "$conf_file" >&2 || echo "(Permission denied)" >&2
            ;;
        D)
            read -p "Delete ALL configs? (y/N): " confirm </dev/tty
            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                configs_found=0
                for conf_file in "$CONFIG_DIR"/*.conf; do
                    if [ -f "$conf_file" ]; then
                        configs_found=1
                        conf_name=$(basename "$conf_file" .conf)
                        echo "- $conf_name" >&2
                        [ -w "$conf_file" ] && rm "$conf_file" || sudo rm "$conf_file"
                    fi
                done
                [ "$configs_found" -eq 0 ] && echo "(No configs found)" >&2 || echo "All configs deleted" >&2
            fi
            ;;
        d)
            read -p "Enter config name: " name </dev/tty
            name=$(sanitize_conf_name "$name")
            conf_file="$CONFIG_DIR/$name.conf"
            [ ! -f "$conf_file" ] && { echo "Config not found" >&2; exit 1; }
            [ -w "$conf_file" ] && rm "$conf_file" || sudo rm "$conf_file"
            echo "Deleted $conf_file" >&2
            ;;
        q|Q)
            exit 0
            ;;
        *)
            echo "Invalid action" >&2
            exit 1
            ;;
    esac
}

# Purge blocklist setup
purge_blocklist() {
    check_sudo
    if [ "$NON_INTERACTIVE" -eq 0 ]; then
        echo "(configs and credentials will be preserved unless removed in the next step)" >&2
        read -p "Confirm, you want to remove blocklist rules and ipsets? (y/N): " confirm_purge </dev/tty
        if [[ ! "$confirm_purge" =~ ^[Yy]$ ]]; then
            echo "Purge aborted; no changes made" >&2
            exit 0
        fi
    else
        echo "Non-interactive mode: Proceeding with purge of blocklist rules and ipsets" >&2
    fi
    echo "Removing blocklist rules and ipsets..." >&2
    if [ "$FIREWALL_BACKEND" = "iptables" ]; then
        if sudo iptables -C "$IPTABLES_CHAIN" -m set --match-set "$IPSET_NAME" src -j DROP 2>/dev/null; then
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Deleting iptables rule for $IPSET_NAME in $IPTABLES_CHAIN" >&2
            sudo iptables -D "$IPTABLES_CHAIN" -m set --match-set "$IPSET_NAME" src -j DROP 2>>"$LOG_FILE" || {
                [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Failed to delete iptables rule for $IPSET_NAME: $(tail -n 1 "$LOG_FILE")" >&2
            }
        else
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: No iptables rule found for $IPSET_NAME in $IPTABLES_CHAIN" >&2
        fi
        if [ "$IPV6_ENABLED" -eq 1 ] && sudo ip6tables -C "$IPTABLES_CHAIN" -m set --match-set "${IPSET_NAME}_v6" src -j DROP 2>/dev/null; then
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Deleting ip6tables rule for ${IPSET_NAME}_v6 in $IPTABLES_CHAIN" >&2
            sudo ip6tables -D "$IPTABLES_CHAIN" -m set --match-set "${IPSET_NAME}_v6" src -j DROP 2>>"$LOG_FILE" || {
                [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Failed to delete ip6tables rule for ${IPSET_NAME}_v6: $(tail -n 1 "$LOG_FILE")" >&2
            }
        else
            [ "$IPV6_ENABLED" -eq 1 ] && [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: No ip6tables rule found for ${IPSET_NAME}_v6 in $IPTABLES_CHAIN" >&2
        fi
        if sudo ipset list "$IPSET_NAME" >/dev/null 2>&1; then
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Destroying ipset $IPSET_NAME" >&2
            sudo ipset destroy "$IPSET_NAME" 2>>"$LOG_FILE" || {
                [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Failed to destroy ipset $IPSET_NAME: $(tail -n 1 "$LOG_FILE")" >&2
            }
        else
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: ipset $IPSET_NAME does not exist" >&2
        fi
        if [ "$IPV6_ENABLED" -eq 1 ] && sudo ipset list "${IPSET_NAME}_v6" >/dev/null 2>&1; then
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Destroying ipset ${IPSET_NAME}_v6" >&2
            sudo ipset destroy "${IPSET_NAME}_v6" 2>>"$LOG_FILE" || {
                [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Failed to destroy ipset ${IPSET_NAME}_v6: $(tail -n 1 "$LOG_FILE")" >&2
            }
        else
            [ "$IPV6_ENABLED" -eq 1 ] && [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: ipset ${IPSET_NAME}_v6 does not exist" >&2
        fi
    else
        if sudo nft list chain ip filter "$IPTABLES_CHAIN" | grep -q "set $IPSET_NAME"; then
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Deleting nftables rule for $IPSET_NAME in $IPTABLES_CHAIN" >&2
            sudo nft delete rule ip filter "$IPTABLES_CHAIN" handle $(sudo nft -a list chain ip filter "$IPTABLES_CHAIN" | grep "set $IPSET_NAME" | awk '{print $NF}') 2>>"$LOG_FILE" || {
                [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Failed to delete nftables rule for $IPSET_NAME: $(tail -n 1 "$LOG_FILE")" >&2
            }
        else
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: No nftables rule found for $IPSET_NAME in $IPTABLES_CHAIN" >&2
        fi
        if [ "$IPV6_ENABLED" -eq 1 ] && sudo nft list chain ip6 filter "$IPTABLES_CHAIN" | grep -q "set ${IPSET_NAME}_v6"; then
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Deleting nftables rule for ${IPSET_NAME}_v6 in $IPTABLES_CHAIN" >&2
            sudo nft delete rule ip6 filter "$IPTABLES_CHAIN" handle $(sudo nft -a list chain ip6 filter "$IPTABLES_CHAIN" | grep "set ${IPSET_NAME}_v6" | awk '{print $NF}') 2>>"$LOG_FILE" || {
                [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Failed to delete nftables rule for ${IPSET_NAME}_v6: $(tail -n 1 "$LOG_FILE")" >&2
            }
        else
            [ "$IPV6_ENABLED" -eq 1 ] && [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: No nftables rule found for ${IPSET_NAME}_v6 in $IPTABLES_CHAIN" >&2
        fi
        if sudo nft list set ip filter "$IPSET_NAME" >/dev/null 2>&1; then
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Deleting nftables set $IPSET_NAME" >&2
            sudo nft delete set ip filter "$IPSET_NAME" 2>>"$LOG_FILE" || {
                [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Failed to delete nftables set $IPSET_NAME: $(tail -n 1 "$LOG_FILE")" >&2
            }
        else
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: nftables set $IPSET_NAME does not exist" >&2
        fi
        if [ "$IPV6_ENABLED" -eq 1 ] && sudo nft list set ip6 filter "${IPSET_NAME}_v6" >/dev/null 2>&1; then
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Deleting nftables set ${IPSET_NAME}_v6" >&2
            sudo nft delete set ip6 filter "${IPSET_NAME}_v6" 2>>"$LOG_FILE" || {
                [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Failed to delete nftables set ${IPSET_NAME}_v6: $(tail -n 1 "$LOG_FILE")" >&2
            }
        else
            [ "$IPV6_ENABLED" -eq 1 ] && [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: nftables set ${IPSET_NAME}_v6 does not exist" >&2
        fi
    fi
    if [ "$NON_INTERACTIVE" -eq 0 ]; then
        echo "Blocklist rules and ipsets removed; configs and credentials preserved." >&2
        read -p "Also delete configs and credentials in $CONFIG_DIR? (y/N): " delete_configs </dev/tty
        if [[ "$delete_configs" =~ ^[Yy]$ ]]; then
            rm -rf "$CONFIG_DIR" "$CRED_FILE"
            echo "Configs and credentials deleted" >&2
        else
            echo "Configs and credentials kept" >&2
        fi
    else
        echo "Non-interactive mode: Configs and credentials preserved" >&2
    fi
    echo "Blocklist purge complete" >&2
}

# Clear blocklist rules from firewall
clear_rules() {
    check_sudo
    if [ "$NON_INTERACTIVE" -eq 0 ]; then
        echo "This will remove blocklist firewall rules, keeping ipsets and configs for fast reapplication." >&2
        read -p "Continue? (y/N): " confirm_clear </dev/tty
        if [[ ! "$confirm_clear" =~ ^[Yy]$ ]]; then
            echo "Clearing aborted" >&2
            return 0
        fi
    fi
    echo "Clearing blocklist firewall rules..." >&2
    if [ "$FIREWALL_BACKEND" = "iptables" ]; then
        if sudo iptables -C "$IPTABLES_CHAIN" -m set --match-set "$IPSET_NAME" src -j DROP 2>/dev/null; then
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Deleting iptables rule for $IPSET_NAME in $IPTABLES_CHAIN" >&2
            sudo iptables -D "$IPTABLES_CHAIN" -m set --match-set "$IPSET_NAME" src -j DROP 2>>"$LOG_FILE" || {
                [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Failed to delete iptables rule for $IPSET_NAME: $(tail -n 1 "$LOG_FILE")" >&2
            }
        else
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: No iptables rule found for $IPSET_NAME in $IPTABLES_CHAIN" >&2
        fi
        if [ "$IPV6_ENABLED" -eq 1 ] && sudo ip6tables -C "$IPTABLES_CHAIN" -m set --match-set "${IPSET_NAME}_v6" src -j DROP 2>/dev/null; then
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Deleting ip6tables rule for ${IPSET_NAME}_v6 in $IPTABLES_CHAIN" >&2
            sudo ip6tables -D "$IPTABLES_CHAIN" -m set --match-set "${IPSET_NAME}_v6" src -j DROP 2>>"$LOG_FILE" || {
                [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Failed to delete ip6tables rule for ${IPSET_NAME}_v6: $(tail -n 1 "$LOG_FILE")" >&2
            }
        else
            [ "$IPV6_ENABLED" -eq 1 ] && [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: No ip6tables rule found for ${IPSET_NAME}_v6 in $IPTABLES_CHAIN" >&2
        fi
    else
        if sudo nft list chain ip filter "$IPTABLES_CHAIN" | grep -q "set $IPSET_NAME"; then
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Deleting nftables rule for $IPSET_NAME in $IPTABLES_CHAIN" >&2
            sudo nft delete rule ip filter "$IPTABLES_CHAIN" handle $(sudo nft -a list chain ip filter "$IPTABLES_CHAIN" | grep "set $IPSET_NAME" | awk '{print $NF}') 2>>"$LOG_FILE" || {
                [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Failed to delete nftables rule for $IPSET_NAME: $(tail -n 1 "$LOG_FILE")" >&2
            }
        else
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: No nftables rule found for $IPSET_NAME in $IPTABLES_CHAIN" >&2
        fi
        if [ "$IPV6_ENABLED" -eq 1 ] && sudo nft list chain ip6 filter "$IPTABLES_CHAIN" | grep -q "set ${IPSET_NAME}_v6"; then
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Deleting nftables rule for ${IPSET_NAME}_v6 in $IPTABLES_CHAIN" >&2
            sudo nft delete rule ip6 filter "$IPTABLES_CHAIN" handle $(sudo nft -a list chain ip6 filter "$IPTABLES_CHAIN" | grep "set ${IPSET_NAME}_v6" | awk '{print $NF}') 2>>"$LOG_FILE" || {
                [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Failed to delete nftables rule for ${IPSET_NAME}_v6: $(tail -n 1 "$LOG_FILE")" >&2
            }
        else
            [ "$IPV6_ENABLED" -eq 1 ] && [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: No nftables rule found for ${IPSET_NAME}_v6 in $IPTABLES_CHAIN" >&2
        fi
    fi
    echo "Blocklist firewall rules cleared; ipsets preserved: re-enable with --apply-rules" >&2
}

purge_all() {
    check_sudo
    local confirm_purge_all="n"
    if [ "$1" = "-y" ] || [ "$1" = "-Y" ]; then
        confirm_purge_all="y"
    fi
    if [ "$NON_INTERACTIVE" -eq 1 ] && [ "$confirm_purge_all" != "y" ]; then
        echo "Error: --purge-all in non-interactive mode requires -y to confirm" >&2
        exit 1
    fi
    if [ "$NON_INTERACTIVE" -eq 0 ] && [ "$confirm_purge_all" != "y" ]; then
        echo "WARNING: This will remove ALL blocklist rules, ipsets, configs, and credentials in $CONFIG_DIR and $CRED_FILE" >&2
        read -p "Confirm purge of ALL blocklist data? (y/N): " confirm_purge_all </dev/tty
        if [[ ! "$confirm_purge_all" =~ ^[Yy]$ ]]; then
            echo "Purge-all aborted; no changes made" >&2
            exit 0
        fi
    fi
    echo "Purging all blocklist rules, ipsets, configs, and credentials..." >&2
    # Reuse purge_blocklist's rule and ipset deletion logic
    if [ "$FIREWALL_BACKEND" = "iptables" ]; then
        if sudo iptables -C "$IPTABLES_CHAIN" -m set --match-set "$IPSET_NAME" src -j DROP 2>/dev/null; then
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Deleting iptables rule for $IPSET_NAME in $IPTABLES_CHAIN" >&2
            sudo iptables -D "$IPTABLES_CHAIN" -m set --match-set "$IPSET_NAME" src -j DROP 2>>"$LOG_FILE" || {
                [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Failed to delete iptables rule for $IPSET_NAME: $(tail -n 1 "$LOG_FILE")" >&2
            }
        else
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: No iptables rule found for $IPSET_NAME in $IPTABLES_CHAIN" >&2
        fi
        if [ "$IPV6_ENABLED" -eq 1 ] && sudo ip6tables -C "$IPTABLES_CHAIN" -m set --match-set "${IPSET_NAME}_v6" src -j DROP 2>/dev/null; then
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Deleting ip6tables rule for ${IPSET_NAME}_v6 in $IPTABLES_CHAIN" >&2
            sudo ip6tables -D "$IPTABLES_CHAIN" -m set --match-set "${IPSET_NAME}_v6" src -j DROP 2>>"$LOG_FILE" || {
                [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Failed to delete ip6tables rule for ${IPSET_NAME}_v6: $(tail -n 1 "$LOG_FILE")" >&2
            }
        else
            [ "$IPV6_ENABLED" -eq 1 ] && [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: No ip6tables rule found for ${IPSET_NAME}_v6 in $IPTABLES_CHAIN" >&2
        fi
        if sudo ipset list "$IPSET_NAME" >/dev/null 2>&1; then
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Destroying ipset $IPSET_NAME" >&2
            sudo ipset destroy "$IPSET_NAME" 2>>"$LOG_FILE" || {
                [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Failed to destroy ipset $IPSET_NAME: $(tail -n 1 "$LOG_FILE")" >&2
            }
        else
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: ipset $IPSET_NAME does not exist" >&2
        fi
        if [ "$IPV6_ENABLED" -eq 1 ] && sudo ipset list "${IPSET_NAME}_v6" >/dev/null 2>&1; then
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Destroying ipset ${IPSET_NAME}_v6" >&2
            sudo ipset destroy "${IPSET_NAME}_v6" 2>>"$LOG_FILE" || {
                [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Failed to destroy ipset ${IPSET_NAME}_v6: $(tail -n 1 "$LOG_FILE")" >&2
            }
        else
            [ "$IPV6_ENABLED" -eq 1 ] && [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: ipset ${IPSET_NAME}_v6 does not exist" >&2
        fi
    else
        if sudo nft list chain ip filter "$IPTABLES_CHAIN" | grep -q "set $IPSET_NAME"; then
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Deleting nftables rule for $IPSET_NAME in $IPTABLES_CHAIN" >&2
            sudo nft delete rule ip filter "$IPTABLES_CHAIN" handle $(sudo nft -a list chain ip filter "$IPTABLES_CHAIN" | grep "set $IPSET_NAME" | awk '{print $NF}') 2>>"$LOG_FILE" || {
                [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Failed to delete nftables rule for $IPSET_NAME: $(tail -n 1 "$LOG_FILE")" >&2
            }
        else
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: No nftables rule found for $IPSET_NAME in $IPTABLES_CHAIN" >&2
        fi
        if [ "$IPV6_ENABLED" -eq 1 ] && sudo nft list chain ip6 filter "$IPTABLES_CHAIN" | grep -q "set ${IPSET_NAME}_v6"; then
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Deleting nftables rule for ${IPSET_NAME}_v6 in $IPTABLES_CHAIN" >&2
            sudo nft delete rule ip6 filter "$IPTABLES_CHAIN" handle $(sudo nft -a list chain ip6 filter "$IPTABLES_CHAIN" | grep "set ${IPSET_NAME}_v6" | awk '{print $NF}') 2>>"$LOG_FILE" || {
                [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Failed to delete nftables rule for ${IPSET_NAME}_v6: $(tail -n 1 "$LOG_FILE")" >&2
            }
        else
            [ "$IPV6_ENABLED" -eq 1 ] && [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: No nftables rule found for ${IPSET_NAME}_v6 in $IPTABLES_CHAIN" >&2
        fi
        if sudo nft list set ip filter "$IPSET_NAME" >/dev/null 2>&1; then
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Deleting nftables set $IPSET_NAME" >&2
            sudo nft delete set ip filter "$IPSET_NAME" 2>>"$LOG_FILE" || {
                [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Failed to delete nftables set $IPSET_NAME: $(tail -n 1 "$LOG_FILE")" >&2
            }
        else
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: nftables set $IPSET_NAME does not exist" >&2
        fi
        if [ "$IPV6_ENABLED" -eq 1 ] && sudo nft list set ip6 filter "${IPSET_NAME}_v6" >/dev/null 2>&1; then
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Deleting nftables set ${IPSET_NAME}_v6" >&2
            sudo nft delete set ip6 filter "${IPSET_NAME}_v6" 2>>"$LOG_FILE" || {
                [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Failed to delete nftables set ${IPSET_NAME}_v6: $(tail -n 1 "$LOG_FILE")" >&2
            }
        else
            [ "$IPV6_ENABLED" -eq 1 ] && [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: nftables set ${IPSET_NAME}_v6 does not exist" >&2
        fi
    fi
    # Delete configs and credentials
    [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Deleting configs in $CONFIG_DIR and credentials in $CRED_FILE" >&2
    rm -rf "$CONFIG_DIR" "$CRED_FILE" 2>>"$LOG_FILE" || {
        [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Failed to delete configs or credentials: $(tail -n 1 "$LOG_FILE")" >&2
    }
    echo "All blocklist rules, ipsets, configs, and credentials purged" >&2
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
        # Validate IPv4 CIDR (strict octet range 0-255)
        if [[ "$range" =~ ^([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(/[0-9]{1,2})?$ ]]; then
            local ip mask
            IFS='/' read -r ip mask <<< "$range"
            [ -z "$mask" ] && mask=32
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
    # Use TEMP_DIR for temporary files
    local wget_output="$TEMP_DIR/wget_output"
    local pv_output="$TEMP_DIR/pv_output"
    # Attempt download with retries
    for attempt in $(seq 1 "$RETRY_ATTEMPTS"); do
        [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Attempt $attempt: wget $fetch_url" >&2
        local wget_cmd="wget -nv -L --timeout=10 --tries=1 -O $temp_raw $fetch_url"
        if command -v pv >/dev/null; then
            # Use pv to show download progress
            if $wget_cmd 2>"$wget_output" && [ -s "$temp_raw" ]; then
                pv -f -N "Downloading $fetch_url" "$temp_raw" > /dev/null 2>"$pv_output"
                [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Download successful; wget output in $wget_output, pv output in $pv_output" >&2
                return 0
            fi
        else
            # Fallback to wget without pv
            if $wget_cmd 2>"$wget_output" && [ -s "$temp_raw" ]; then
                [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Download successful; wget output in $wget_output" >&2
                return 0
            fi
        fi
        local wget_error=$(cat "$wget_output")
        if echo "$wget_error" | grep -q "403 Forbidden" >&2; then
            echo "Authentication failed for $fetch_url" >&2
            return 1
        elif echo "$wget_error" | grep -q "429 Too Many Requests" >&2; then
            echo "Rate limit exceeded for $fetch_url" >&2
        else
            echo "Download attempt $attempt failed: $wget_error" >&2
        fi
        [ "$attempt" -lt "$RETRY_ATTEMPTS" ] && { echo "Retrying in $RETRY_DELAY seconds..."; sleep "$RETRY_DELAY"; }
    done
    echo "Failed to download $fetch_url after $RETRY_ATTEMPTS attempts" >&2
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
    local was_set_x=0
    [ "$VERBOSE_DEBUG" -eq 1 ] && { set +x; was_set_x=1; }
    if command -v pv >/dev/null; then
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
            # Trim leading/trailing whitespace with parameter expansion
            range="${line##[[:space:]]*}"; range="${range%%[[:space:]]*}"
            # Try name:range format
            if [[ "$range" =~ ^[^:]+:([0-9a-fA-F.:/]+)$ ]]; then
                range="${BASH_REMATCH[1]}"
            fi
            # Check if IPv4 CIDR (e.g., 192.168.1.0/24)
            if [[ "$range" =~ ^([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(/[0-9]{1,2})?$ ]]; then
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
                    echo "Invalid IPv4 CIDR in $conf_file: $range" >&2
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
                    echo "Invalid IPv6 CIDR in $conf_file: $range" >&2
                fi
            elif [[ "$range" =~ ^[0-9a-fA-F:]+(/[0-9]{1,3})?$ ]]; then
                if [ "$NON_INTERACTIVE" -eq 1 ]; then
                    [ "$NON_INTERACTIVE_LOG_IPV6" = "y" ] && echo "$range" >> "$LOG_FILE.ipv6"
                else
                    read -p "IPv6 detected in $conf_file. Log to $LOG_FILE.ipv6? (y/N): " log_ipv6 </dev/tty
                    if [[ "$log_ipv6" =~ ^[Yy]$ ]]; then
                        echo "$range" >> "$LOG_FILE.ipv6"
                        chmod 600 "$LOG_FILE.ipv6" 2>>"$LOG_FILE"
                    fi
                fi
            else
                echo "Skipping non-CIDR in $conf_file: $range" >&2
            fi
            # Write batch every 10,000 lines to balance memory and I/O
            if [ $((cidr_count % 10000)) -eq 0 ] && [ -n "$batch" ]; then
                echo -e "$batch" | sed '/^$/d' >> "$IP_LIST"
                batch=""
            fi
        done < <(pv -f -N "Parsing $conf_file" -s "$total_lines" "$temp_list")
    else
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
            # Trim leading/trailing whitespace with parameter expansion
            range="${line##[[:space:]]*}"; range="${range%%[[:space:]]*}"
            # Try name:range format
            if [[ "$range" =~ ^[^:]+:([0-9a-fA-F.:/]+)$ ]]; then
                range="${BASH_REMATCH[1]}"
            fi
            # Check if IPv4 CIDR (e.g., 192.168.1.0/24)
            if [[ "$range" =~ ^([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])(/[0-9]{1,2})?$ ]]; then
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
                    echo "Invalid IPv4 CIDR in $conf_file: $range" >&2
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
                    echo "Invalid IPv6 CIDR in $conf_file: $range" >&2
                fi
            elif [[ "$range" =~ ^[0-9a-fA-F:]+(/[0-9]{1,3})?$ ]]; then
                if [ "$NON_INTERACTIVE" -eq 1 ]; then
                    [ "$NON_INTERACTIVE_LOG_IPV6" = "y" ] && echo "$range" >> "$LOG_FILE.ipv6"
                else
                    read -p "IPv6 detected in $conf_file. Log to $LOG_FILE.ipv6? (y/N): " log_ipv6 </dev/tty
                    if [[ "$log_ipv6" =~ ^[Yy]$ ]]; then
                        echo "$range" >> "$LOG_FILE.ipv6"
                        chmod 600 "$LOG_FILE.ipv6" 2>>"$LOG_FILE"
                    fi
                fi
            else
                echo "Skipping non-CIDR in $conf_file: $range" >&2
            fi
            # Write batch every 10,000 lines to balance memory and I/O
            if [ $((cidr_count % 10000)) -eq 0 ] && [ -n "$batch" ]; then
                echo -e "$batch" | sed '/^$/d' >> "$IP_LIST"
                batch=""
            fi
        done < "$temp_list"
    fi
    # Write any remaining lines
    [ -n "$batch" ] && echo -e "$batch" | sed '/^$/d' >> "$IP_LIST"
    [ "$was_set_x" -eq 1 ] && set -x
    [ "$DEBUG_MODE" -eq 1 ] && {
        echo "DEBUG: Found $cidr_count CIDRs, skipped $skipped_empty empty lines, $skipped_comments comments in $temp_list" >&2
    }
    echo "Added $cidr_count CIDRs from $conf_file" >&2
    if [ "$cidr_count" -eq 0 ]; then
        echo "Warning: No valid CIDRs found in $conf_file" >&2
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
    temp_list="$TEMP_DIR/iplist_$(basename "$conf_file").XXXXXX"
    touch "$temp_list" || { echo "Error: Failed to create temp file $temp_list for $conf_file" >&2; return 1; }
    chmod 600 "$temp_list"
    # Parse config
    local URL USERNAME PIN
    URL=$(grep '^URL=' "$conf_file" | cut -d= -f2-)
    USERNAME=$(grep '^USERNAME=' "$conf_file" | cut -d= -f2-)
    PIN=$(grep '^PIN=' "$conf_file" | cut -d= -f2-)
    [ -z "$URL" ] && { echo "Skipping $conf_file: No URL" >&2; rm -f "$temp_list"; return 1; }
    local clean_url stripped_user stripped_pin
    read clean_url stripped_user stripped_pin < <(sanitize_url "$URL" | tr '|' ' ')
    if [ -n "$stripped_user" ] || [ -n "$stripped_pin" ]; then
        echo "Warning: Credentials in $conf_file URL ignored" >&2
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
    [ ! -s "$IP_LIST_RAW" ] && { echo "Downloaded file empty" >&2; rm -f "$temp_list"; return 1; }
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
        gunzip -c "$IP_LIST_RAW" > "$temp_list" || { echo "Failed to decompress gzip" >&2; rm -f "$temp_list"; return 1; }
    elif echo "$file_type" | grep -q "Zip archive"; then
        command -v unzip >/dev/null || { echo "Error: unzip required"; rm -f "$temp_list"; return 1; }
        unzip -p "$IP_LIST_RAW" > "$temp_list" || { echo "Failed to decompress zip" >&2; rm -f "$temp_list"; return 1; }
    elif echo "$file_type" | grep -q "7-zip archive"; then
        command -v 7z >/dev/null || { echo "Error: 7z required"; rm -f "$temp_list"; return 1; }
        7z e -so "$IP_LIST_RAW" > "$temp_list" || { echo "Failed to decompress 7z" >&2; rm -f "$temp_list"; return 1; }
    else
        echo "Unsupported archive format" >&2
        rm -f "$temp_list"
        return 1
    fi
    [ ! -s "$temp_list" ] && { echo "Decompressed file empty" >&2; rm -f "$temp_list"; return 1; }
    # Parse
    parse_blocklist "$conf_file" "$temp_list"
    local status=$?
    rm -f "$temp_list"
    return $status
}

# Add CIDRs to set (for iptables only, nftables handled in apply_ipset)
add_to_set() {
    local family="$1" cidr="$2" set_name="$3"
    echo "add $set_name $cidr"
    [ "$DEBUG_MODE" -eq 1 ] && [ "$cidr_count" -le 5 ] && echo "DEBUG: Adding $cidr to $set_name" >&2
}

# Apply set changes (unused, kept for compatibility)
apply_set() {
    local set_name="$1"
    return 0
}

# Backup existing set
backup_set() {
    local set_name="$1"
    if [ "$FIREWALL_BACKEND" = "iptables" ]; then
        [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Checking if ipset $set_name exists before backup" >&2
        if sudo ipset list "$set_name" >/dev/null 2>&1; then
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Backing up ipset $set_name to $IPSET_BACKUP_FILE" >&2
            sudo ipset save "$set_name" -file "$IPSET_BACKUP_FILE" 2>>"$LOG_FILE" || {
                echo "Warning: Failed to back up ipset $set_name" >&2
            }
        else
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: ipset $set_name does not exist; no backup needed" >&2
        fi
    else
        [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Checking if nft set $set_name exists before backup" >&2
        if sudo nft list set ip filter "$set_name" >/dev/null 2>&1 || sudo nft list set ip6 filter "$set_name" >/dev/null 2>&1; then
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Backing up nft set $set_name to $IPSET_BACKUP_FILE" >&2
            sudo nft list set ip filter "$set_name" > "$IPSET_BACKUP_FILE" 2>>"$LOG_FILE" || \
            sudo nft list set ip6 filter "$set_name" > "$IPSET_BACKUP_FILE" 2>>"$LOG_FILE"
        else
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: nft set $set_name does not exist; no backup needed" >&2
        fi
    fi
}

# Apply firewall rule
apply_rule() {
    local family="$1" set_name="$2"
    if [ "$FIREWALL_BACKEND" = "iptables" ]; then
        if sudo ipset list "$set_name" >/dev/null 2>&1; then
            [ "$(sudo ipset list "$set_name" | grep -c '^Name:')" -eq 0 ] && { echo "ERROR: IP set $set_name is empty" >&2; return 1; }
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Checking/adding iptables rule for $set_name" >&2
            sudo iptables -C "$IPTABLES_CHAIN" -m set --match-set "$set_name" src -j DROP 2>/dev/null || \
            sudo iptables -I "$IPTABLES_CHAIN" -m set --match-set "$set_name" src -j DROP || {
                echo "ERROR: Failed to add iptables rule for $set_name" >&2
                return 1
            }
        else
            echo "ERROR: IP set $set_name does not exist or is inaccessible" >&2
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: ipset list output: $(sudo ipset list "$set_name" 2>&1)" >&2
            return 1
        fi
    else
        if nft list set "$family" filter "$set_name" >/dev/null 2>&1; then
            if [ "$family" = "inet" ]; then
                [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Adding nft rule for $set_name (IPv4)" >&2
                sudo nft add rule ip filter "$IPTABLES_CHAIN" ip saddr "@$set_name" drop || {
                    echo "ERROR: Failed to add nft rule for $set_name (IPv4)" >&2
                    return 1
                }
            else
                [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Adding nft rule for $set_name (IPv6)" >&2
                sudo nft add rule ip6 filter "$IPTABLES_CHAIN" ip6 saddr "@$set_name" drop || {
                    echo "ERROR: Failed to add nft rule for $set_name (IPv6)" >&2
                    return 1
                }
            fi
        else
            echo "ERROR: NFT set $set_name does not exist" >&2
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: nft list set output: $(nft list set "$family" filter "$set_name" 2>&1)" >&2
            return 1
        fi
    fi
    return 0
}

# Function to apply CIDRs to ipset or nftables set
apply_ipset() {
    local family="$1" set_name="$2" ipset_file="$3" expected_count="$4"
    local tmp_script
    tmp_script="$TEMP_DIR/ipset_commands"
    touch "$tmp_script" || { echo "Error: Failed to create $tmp_script" >&2; exit 1; }
    chmod 660 "$tmp_script"
    if [ "$DRY_RUN" -eq 1 ]; then
        echo "Dry run: Would apply $set_name from $ipset_file ($expected_count entries)" >&2
        rm -f "$tmp_script"
        return 0
    fi
    # Debug: Show first and last 5 lines of ipset_file
    [ "$DEBUG_MODE" -eq 1 ] && {
        echo "DEBUG: First 5 lines of $ipset_file:" >&2
        head -n 5 "$ipset_file" >&2
        echo "DEBUG: Last 5 lines of $ipset_file:" >&2
        tail -n 5 "$ipset_file" >&2
    }
    local actual_count=$(wc -l < "$ipset_file")
    check_sudo
    if [ "$FIREWALL_BACKEND" = "iptables" ]; then
        # Destroy existing set to avoid conflicts
        sudo ipset destroy "$set_name" 2>>"$LOG_FILE" || true
        # Calculate hashsize and maxelem
        local hashsize maxelem
        hashsize=$(awk -v n="$expected_count" 'BEGIN { n = n * 1.5; logval = log(n)/log(2); print 2^int(logval+1) }')
        maxelem=$((expected_count * 2))
        [ $hashsize -lt 1024 ] && hashsize=1024
        [ $maxelem -lt 1024 ] && maxelem=1024
        [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Calculated hashsize=$hashsize, maxelem=$maxelem for $set_name" >&2
        # Create new ipset
        [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Creating ipset $set_name" >&2
        sudo ipset create "$set_name" hash:net hashsize "$hashsize" family "$family" maxelem "$maxelem" 2>>"$LOG_FILE" || {
            echo "Error: Failed to create ipset $set_name" >&2
            rm -f "$tmp_script"
            exit 1
        }
        # Populate ipset
        echo "flush $set_name" > "$tmp_script"
        local cidr_count=0
        local was_set_x=0
        [ "$VERBOSE_DEBUG" -eq 1 ] && { set +x; was_set_x=1; }
        if command -v pv >/dev/null; then
            while IFS= read -r cidr; do
                [ -z "$cidr" ] && continue
                if validate_cidr "$cidr" "$family"; then
                    if [ "$IPSET_TEST" -eq 1 ] && sudo ipset test "$set_name" "$cidr" 2>/dev/null; then
                        [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Skipping duplicate $family CIDR $cidr in $set_name" >&2
                    else
                        echo "add $set_name $cidr" >> "$tmp_script"
                        ((cidr_count++))
                    fi
                else
                    echo "Invalid $family CIDR skipped: $cidr" >&2
                fi
            done < <(pv -f -N "Applying $family CIDRs to $set_name" -s "$actual_count" "$ipset_file")
        [ "$was_set_x" -eq 1 ] && set -x
        else
            while IFS= read -r cidr; do
                [ -z "$cidr" ] && continue
                if [ "$IPSET_TEST" -eq 1 ] && sudo ipset test "$set_name" "$cidr" 2>/dev/null; then
                    [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Skipping duplicate $family CIDR $cidr in $set_name" >&2
                else
                    echo "add $set_name $cidr" >> "$tmp_script" || { echo "Error: Failed to write to $tmp_script" >&2; rm -f "$tmp_script"; exit 1; }
                fi
                ((cidr_count++))
            done < "$ipset_file"
        fi
        # Debug: Log tmp_script if no CIDRs applied
        if [ "$cidr_count" -eq 0 ]; then
            echo "ERROR: No valid CIDRs applied to $set_name" >&2
        fi
        if [ "$DEBUG_MODE" -eq 1 ] && [ -s "$tmp_script" ]; then
            echo "DEBUG: First 5 lines of $tmp_script:" >&2
            head -n 5 "$tmp_script" >&2
            echo "DEBUG: Last 5 lines of $tmp_script:" >&2
            tail -n 5 "$tmp_script" >&2
        fi
        # Debug: Log tmp_script permissions
        if [ "$DEBUG_MODE" -eq 1 ]; then
            echo "DEBUG: Permissions of $tmp_script:" >&2
            ls -l "$tmp_script" >&2
        fi
        # Apply ipset commands with chunking
        local ipset_output ipset_status chunk_size=100000 attempts=0 max_attempts=3
        split -l 10000 "$tmp_script" "$TEMP_DIR/ipset_chunk_" || { echo "Error: Failed to split $tmp_script into chunks" >&2; rm -f "$tmp_script"; exit 1; }
        for chunk in "$TEMP_DIR"/ipset_chunk_*; do
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Processing chunk $chunk" >&2
            ipset_output=$(sudo ipset restore < "$chunk" 2>&1)
            ipset_status=$?
            if [ $ipset_status -ne 0 ]; then
                echo "Error: Failed to apply ipset chunk $chunk: $ipset_output" >&2
                rm -f "$tmp_script" "$TEMP_DIR"/ipset_chunk_*
                exit 1
            fi
        done
        rm -f "$TEMP_DIR"/ipset_chunk_*
        # Verify ipset exists
        sudo ipset list "$set_name" >/dev/null 2>&1 || { echo "Error: IP set $set_name does not exist after apply_ipset" >&2; rm -f "$tmp_script" "$TEMP_DIR"/ipset_chunk_*; exit 1; }
        ipset_status=$?
        while [ $ipset_status -ne 0 ] && [ $attempts -lt $max_attempts ]; do
            echo "Failed to apply ipset $set_name: $ipset_output" >&2
            echo "Attempting fallback with chunk size $chunk_size..." >&2
            split -l "$chunk_size" "$tmp_script" ipset_chunk_
            sudo ipset destroy "$set_name" 2>>"$LOG_FILE" || true
            sudo ipset create "$set_name" hash:net hashsize "$hashsize" family "$family" maxelem "$maxelem" 2>>"$LOG_FILE"
            for chunk in ipset_chunk_*; do
                ipset_output=$(sudo ipset restore < "$chunk" 2>&1)
                ipset_status=$?
                if [ $ipset_status -ne 0 ]; then
                    echo "Failed to apply chunk $chunk: $ipset_output" >&2
                    break
                fi
            done
            rm -f ipset_chunk_*
            attempts=$((attempts + 1))
            chunk_size=$((chunk_size / 2))
            [ $chunk_size -lt 1000 ] && chunk_size=1000
        done
        if [ $ipset_status -ne 0 ]; then
            echo "Failed to apply ipset $set_name after $max_attempts attempts" >&2
            if [ -s "$IPSET_BACKUP_FILE" ]; then
                if sudo ipset restore < "$IPSET_BACKUP_FILE" 2>>"$LOG_FILE"; then
                    echo "Restored previous state"
                    apply_rule "$family" "$set_name"
                else
                    echo "Failed to restore backup" >&2
                fi
            fi
            rm -f "$tmp_script"
            exit 1
        fi
        echo "Applied $cidr_count entries to $set_name" >&2
    else
        # Nftables: Use bulk loading
        sudo nft delete set "$family" filter "$set_name" 2>>"$LOG_FILE" || true
        [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Creating nftables set $set_name" >&2
        if [ "$family" = "inet" ]; then
            sudo nft add set ip filter "$set_name" "{ type ipv4_addr; flags interval; }" 2>>"$LOG_FILE" || {
                echo "Error: Failed to create nftables set $set_name (IPv4)" >&2
                rm -f "$tmp_script"
                exit 1
            }
        else
            sudo nft add set ip6 filter "$set_name" "{ type ipv6_addr; flags interval; }" 2>>"$LOG_FILE" || {
                echo "Error: Failed to create nftables set $set_name (IPv6)" >&2
                rm -f "$tmp_script"
                exit 1
            }
        fi
        # Populate nftables set
        local cidr_count=0
        local nft_commands=""
        if command -v pv >/dev/null; then
            pv -f -N "Applying $family CIDRs to $set_name" -s "$expected_count" "$ipset_file" | while IFS= read -r cidr; do
                [ -z "$cidr" ] && continue
                nft_commands="$nft_commands    add element $family filter $set_name { $cidr }\n"
                ((cidr_count++))
            done
        else
            while IFS= read -r cidr; do
                [ -z "$cidr" ] && continue
                nft_commands="$nft_commands    add element $family filter $set_name { $cidr }\n"
                ((cidr_count++))
            done < "$ipset_file"
        fi
        # Apply nftables commands
        if [ -n "$nft_commands" ]; then
            echo -e "define set_name = $set_name\nadd table $family filter\n$nft_commands" > "$tmp_script"
            sudo nft -f "$tmp_script" 2>>"$LOG_FILE" || {
                echo "Error: Failed to apply nftables set $set_name" >&2
                rm -f "$tmp_script"
                exit 1
            }
        fi
        echo "Applied $cidr_count entries to $set_name" >&2
    fi
    rm -f "$tmp_script"
}

# Update blocklist
update_blocklist() {
    local dry_run="$1"
    check_sudo
    check_dependencies
    setup_config_dir
    [ ! -d "$CONFIG_DIR" ] || ! ls "$CONFIG_DIR"/*.conf >/dev/null 2>&1 && { echo "No configs in $CONFIG_DIR. Use --config" >&2; exit 1; }
    : > "$IP_LIST"
    local total_cidr=0
    for conf_file in "$CONFIG_DIR"/*.conf; do
        if [ -f "$conf_file" ]; then
            echo "Processing $conf_file... (at $(date))" >&2
            if process_blocklist "$conf_file"; then
                local cidrs=$(grep -c '^inet' "$IP_LIST")
                [ "$IPV6_ENABLED" -eq 1 ] && cidrs=$((cidrs + $(grep -c '^inet6' "$IP_LIST")))
                total_cidr=$((total_cidr + cidrs))
            fi
        fi
    done
    if [ -s "$IP_LIST" ]; then
        if [ "$total_cidr" -gt 100000 ]; then
            echo "Warning: $total_cidr CIDRs detected across all blocklists; processing may take significant time." >&2
            if [ "$NON_INTERACTIVE" -eq 0 ]; then
                read -p "Continue? (y/N): " continue_large </dev/tty
                [[ ! "$continue_large" =~ ^[Yy]$ ]] && { echo "Aborted" >&2; exit 0; }
            fi
        fi
    else
        echo "No valid CIDRs retrieved" >&2
        exit 1
    fi
    echo "First and last 5 lines of merged list:" >&2
    head -n 5 "$IP_LIST"
    tail -n 5 "$IP_LIST"
    echo "Total valid CIDRs: $total_cidr" >&2
    echo "Duplicate CIDRs:" >&2
    local dupes=$(LC_ALL=C sort "$IP_LIST" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | uniq -d | wc -l)
    echo "$dupes" >&2
    echo "------------------------" >&2
    [ "$dry_run" -eq 1 ] && { echo "Dry run: Would apply $((total_cidr - dupes)) entries" >&2; return 0; }
    # Aggregate CIDRs
    AGGREGATED_CIDR_LIST="$TEMP_DIR/aggregated_cidr_list"
    AGGREGATED_CIDR_LIST_V6="$TEMP_DIR/aggregated_cidr_list_v6"
    touch "$AGGREGATED_CIDR_LIST" "$AGGREGATED_CIDR_LIST_V6" || { echo "Error: Failed to create temp files $AGGREGATED_CIDR_LIST or $AGGREGATED_CIDR_LIST_V6" >&2; exit 1; }
    chmod 660 "$AGGREGATED_CIDR_LIST" "$AGGREGATED_CIDR_LIST_V6"
    [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Created temporary files $AGGREGATED_CIDR_LIST and $AGGREGATED_CIDR_LIST_V6" >&2
    # Check for large CIDR counts without aggregate in interactive mode
    if [ "$NO_IPV4_MERGE" != "y" ] && ! command -v aggregate >/dev/null && [ -s "$IP_LIST" ]; then
        num_ipv4=$(grep -c '^inet' "$IP_LIST")
        if [ "$num_ipv4" -gt 10000 ]; then
            if [ "$NON_INTERACTIVE" -eq 0 ]; then
                echo "Warning: 'aggregate' not found and $num_ipv4 IPv4 CIDRs detected; Bash merging may be slow" >&2
                read -p "Skip IPv4 merging to avoid delays (risks overlaps)? (y/N): " skip_merge </dev/tty
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
                echo "Warning: 'aggregate6' not found and $num_ipv6 IPv6 CIDRs detected; Bash merging may be slow" >&2
                read -p "Skip IPv6 merging to avoid delays (risks overlaps)? (y/N): " skip_merge_v6 </dev/tty
                [[ "$skip_merge_v6" =~ ^[Yy]$ ]] && NO_IPV6_MERGE=1
            elif [ "$NON_INTERACTIVE_SKIP_MERGE" = "y" ]; then
                NO_IPV6_MERGE=1
            fi
        fi
    fi
    # IPv4 aggregation
    if [ "$NO_IPV4_MERGE" = "y" ]; then
        grep '^inet' "$IP_LIST" | cut -d' ' -f2 | sed '/^[[:space:]]*$/d' > "$AGGREGATED_CIDR_LIST"
    elif command -v aggregate >/dev/null && [ -s "$IP_LIST" ]; then
        grep '^inet' "$IP_LIST" | cut -d' ' -f2 | sed '/^[[:space:]]*$/d' | aggregate -q > "$AGGREGATED_CIDR_LIST"
    else
        grep '^inet' "$IP_LIST" | cut -d' ' -f2 | sed '/^[[:space:]]*$/d' > "$AGGREGATED_CIDR_LIST.tmp"
        merge_cidrs_bash "$AGGREGATED_CIDR_LIST.tmp" "$AGGREGATED_CIDR_LIST"
        rm -f "$AGGREGATED_CIDR_LIST.tmp"
    fi
    
    # IPv6 aggregation
    if [ "$IPV6_ENABLED" -eq 1 ]; then
        if [ "$NO_IPV6_MERGE" = "y" ]; then
            grep '^inet6' "$IP_LIST" | cut -d' ' -f2 > "$AGGREGATED_CIDR_LIST_V6"
        elif command -v aggregate6 >/dev/null && [ -s "$IP_LIST" ]; then
            grep '^inet6' "$IP_LIST" | cut -d' ' -f2 | aggregate6 -q > "$AGGREGATED_CIDR_LIST_V6"
        else
            grep '^inet6' "$IP_LIST" | cut -d' ' -f2 > "$AGGREGATED_CIDR_LIST_V6.tmp"
            merge_cidrs_bash_ipv6 "$AGGREGATED_CIDR_LIST_V6.tmp" "$AGGREGATED_CIDR_LIST_V6"
            rm -f "$AGGREGATED_CIDR_LIST_V6.tmp"
        fi
    fi
    # Verify iptables chain
    if [ "$FIREWALL_BACKEND" = "iptables" ]; then
        [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Verifying iptables chain $IPTABLES_CHAIN exists" >&2
        if ! sudo iptables -L "$IPTABLES_CHAIN" >/dev/null 2>&1; then
            echo "Warning: iptables chain $IPTABLES_CHAIN does not exist" >&2
            if [ "$NON_INTERACTIVE" -eq 0 ]; then
                read -p "Create chain $IPTABLES_CHAIN? (y/N): " create_chain </dev/tty
                if [[ "$create_chain" =~ ^[Yy]$ ]]; then
                    [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Creating iptables chain $IPTABLES_CHAIN" >&2
                    sudo iptables -N "$IPTABLES_CHAIN" || {
                        echo "Error: Failed to create iptables chain $IPTABLES_CHAIN" >&2
                        exit 1
                    }
                    [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: iptables chain $IPTABLES_CHAIN created successfully" >&2
                else
                    echo "Aborted due to missing iptables chain" >&2
                    exit 1
                fi
            elif [ "$NON_INTERACTIVE_CREATE_CHAIN" = "y" ]; then
                [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Non-interactive mode: Creating iptables chain $IPTABLES_CHAIN" >&2
                sudo iptables -N "$IPTABLES_CHAIN" || {
                    echo "Error: Failed to create iptables chain $IPTABLES_CHAIN" >&2
                    exit 1
                }
                [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: iptables chain $IPTABLES_CHAIN created successfully" >&2
            else
                echo "Error: iptables chain $IPTABLES_CHAIN does not exist and non-interactive mode prevents creation" >&2
                exit 1
            fi
        fi
        [ "$IPV6_ENABLED" -eq 1 ] && {
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Verifying ip6tables chain $IPTABLES_CHAIN exists" >&2
            if ! sudo ip6tables -L "$IPTABLES_CHAIN" >/dev/null 2>&1; then
                echo "Warning: ip6tables chain $IPTABLES_CHAIN does not exist" >&2
                if [ "$NON_INTERACTIVE" -eq 0 ]; then
                    read -p "Create ip6tables chain $IPTABLES_CHAIN? (y/N): " create_chain_v6 </dev/tty
                    if [[ "$create_chain_v6" =~ ^[Yy]$ ]]; then
                        [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Creating ip6tables chain $IPTABLES_CHAIN" >&2
                        sudo ip6tables -N "$IPTABLES_CHAIN" || {
                            echo "Error: Failed to create ip6tables chain $IPTABLES_CHAIN" >&2
                            exit 1
                        }
                        [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: ip6tables chain $IPTABLES_CHAIN created successfully" >&2
                    else
                        echo "Aborted due to missing ip6tables chain" >&2
                        exit 1
                    fi
                elif [ "$NON_INTERACTIVE_CREATE_CHAIN" = "y" ]; then
                    [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Non-interactive mode: Creating ip6tables chain $IPTABLES_CHAIN" >&2
                    sudo ip6tables -N "$IPTABLES_CHAIN" || {
                        echo "Error: Failed to create ip6tables chain $IPTABLES_CHAIN" >&2
                        exit 1
                    }
                    [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: ip6tables chain $IPTABLES_CHAIN created successfully" >&2
                else
                    echo "Error: ip6tables chain $IPTABLES_CHAIN does not exist and non-interactive mode prevents creation" >&2
                    exit 1
                fi
            fi
        }
    fi
    # Backup existing sets
    if [ -s "$IPSET_BACKUP_FILE" ]; then
        if [ "$NON_INTERACTIVE" -eq 0 ]; then
            read -p "Backup exists. Overwrite? (y/N): " overwrite_backup </dev/tty
            if [[ ! "$overwrite_backup" =~ ^[Yy]$ ]]; then
                if [ "$NON_INTERACTIVE_CONTINUE_NO_BACKUP" != "y" ]; then
                    echo "Aborted due to existing backup" >&2
                    exit 1
                fi
            fi
        fi
    fi
    [ -s "$AGGREGATED_CIDR_LIST" ] && backup_set "$IPSET_NAME"
    [ "$IPV6_ENABLED" -eq 1 ] && [ -s "$AGGREGATED_CIDR_LIST_V6" ] && backup_set "${IPSET_NAME}_v6"
    # Apply CIDRs
    local ipv4_count=0 ipv6_count=0
    if [ -s "$AGGREGATED_CIDR_LIST" ]; then
        ipv4_count=$(wc -l < "$AGGREGATED_CIDR_LIST")
        apply_ipset inet "$IPSET_NAME" "$AGGREGATED_CIDR_LIST" "$ipv4_count"
        apply_rule inet "$IPSET_NAME"
    fi
    if [ "$IPV6_ENABLED" -eq 1 ] && [ -s "$AGGREGATED_CIDR_LIST_V6" ]; then
        ipv6_count=$(wc -l < "$AGGREGATED_CIDR_LIST_V6")
        apply_ipset inet6 "${IPSET_NAME}_v6" "$AGGREGATED_CIDR_LIST_V6" "$ipv6_count"
        apply_rule inet6 "${IPSET_NAME}_v6"
    fi
    echo "IPv4 CIDRs after merging: $ipv4_count" >&2
    echo "IPv6 CIDRs after merging: $ipv6_count" >&2
    
    # Verify ipset and iptables rules in debug mode
    if [ "$DEBUG_MODE" -eq 1 ]; then
        echo "DEBUG: Listing current ipset rulesets" >&2
        sudo ipset list -name | sed 's/^/DEBUG:   /' >&2 || {
            echo "DEBUG: No ipset rulesets found" >&2
        }
        if [ -s "$AGGREGATED_CIDR_LIST" ]; then
            echo "DEBUG: Verifying iptables rule for $IPSET_NAME" >&2
            echo "DEBUG: iptables rule:" >&2
            sudo iptables -L "$IPTABLES_CHAIN" -v -n | grep -E "match-set $IPSET_NAME src" | sed 's/^/DEBUG:   /' >&2 || {
                echo "DEBUG: No iptables rule found for $IPSET_NAME in chain $IPTABLES_CHAIN" >&2
            }
            echo "DEBUG: Counting entries in ipset $IPSET_NAME..." >&2
            local ipset_count
            ipset_count=$(sudo ipset list "$IPSET_NAME" | grep -v '^Name:\|^Size\|^References:\|^Header:' | wc -l)
            echo "DEBUG: ipset $IPSET_NAME contains $ipset_count entries" >&2
        fi
        if [ "$IPV6_ENABLED" -eq 1 ] && [ -s "$AGGREGATED_CIDR_LIST_V6" ]; then
            echo "DEBUG: Verifying ip6tables rule for ${IPSET_NAME}_v6" >&2
            echo "DEBUG: ip6tables rule:" >&2
            sudo ip6tables -L "$IPTABLES_CHAIN" -v -n | grep -E "match-set ${IPSET_NAME}_v6 src" | sed 's/^/DEBUG:   /' >&2 || {
                echo "DEBUG: No ip6tables rule found for ${IPSET_NAME}_v6 in chain $IPTABLES_CHAIN" >&2
            }
            echo "DEBUG: Counting entries in ipset ${IPSET_NAME}_v6..." >&2
            local ipset_v6_count
            ipset_v6_count=$(sudo ipset list "${IPSET_NAME}_v6" | grep -v '^Name:\|^Size\|^References:\|^Header:' | wc -l)
            echo "DEBUG: ipset ${IPSET_NAME}_v6 contains $ipset_v6_count entries" >&2
        fi
    fi

    # Clean up temporary files
    rm -f "$AGGREGATED_CIDR_LIST" "$AGGREGATED_CIDR_LIST_V6"
    # Calculate and display runtime
    END_TIME=$(date +%s)
    RUNTIME=$((END_TIME - START_TIME))
    echo "Blocklist update completed in $RUNTIME seconds" >&2
}

# Function to display status of ipset/nftables sets and iptables/nftables rules
show_status() {
    check_sudo
    echo "=== Blocklist Status (at $(date)) ==="

    # Determine firewall backend and set/chain names
    local set_name_ipv4="$IPSET_NAME"
    local set_name_ipv6="${IPSET_NAME}_v6"
    local chain="$IPTABLES_CHAIN"
    local total_entries=0

    # ipset/nftables sets
    echo -e "\n--- Blocklist Sets ---"
    if [ "$FIREWALL_BACKEND" = "iptables" ]; then
        # IPv4 ipset
        if sudo ipset list "$set_name_ipv4" >/dev/null 2>&1; then
            local count_ipv4=$(sudo ipset list "$set_name_ipv4" | grep -E '^[0-9]' | wc -l)
            total_entries=$((total_entries + count_ipv4))
            echo "Set: $set_name_ipv4 (IPv4)"
            echo "Entries: $count_ipv4"
            # Show sample entries (up to 5) for user verification
            echo "Sample Entries (up to 5):"
            sudo ipset list "$set_name_ipv4" | grep -E '^[0-9]' | head -n 5 || echo "(None)"
            [ $count_ipv4 -gt 5 ] && echo "... (showing first 5 entries, total: $count_ipv4)"
        else
            echo "Set: $set_name_ipv4 (IPv4, not found)"
        fi
        # IPv6 ipset
        if [ "$IPV6_ENABLED" -eq 1 ]; then
            if sudo ipset list "$set_name_ipv6" >/dev/null 2>&1; then
                local count_ipv6=$(sudo ipset list "$set_name_ipv6" | grep -E '^[0-9a-fA-F]' | wc -l)
                total_entries=$((total_entries + count_ipv6))
                echo "Set: $set_name_ipv6 (IPv6)"
                echo "Entries: $count_ipv6"
                echo "Sample Entries (up to 5):"
                sudo ipset list "$set_name_ipv6" | grep -E '^[0-9a-fA-F]' | head -n 5 || echo "(None)"
                [ $count_ipv6 -gt 5 ] && echo "... (showing first 5 entries, total: $count_ipv6)"
            else
                echo "Set: $set_name_ipv6 (IPv6, not found)"
            fi
        else
            echo "Set: $set_name_ipv6 (IPv6, disabled)"
        fi
    else
        # nftables IPv4 set
        if sudo nft list set ip filter "$set_name_ipv4" >/dev/null 2>&1; then
            local count_ipv4=$(sudo nft list set ip filter "$set_name_ipv4" | grep -E '^[[:space:]]+[0-9]' | wc -l)
            total_entries=$((total_entries + count_ipv4))
            echo "Set: $set_name_ipv4 (IPv4)"
            echo "Entries: $count_ipv4"
            echo "Sample Entries (up to 5):"
            sudo nft list set ip filter "$set_name_ipv4" | grep -E '^[[:space:]]+[0-9]' | head -n 5 || echo "(None)"
            [ $count_ipv4 -gt 5 ] && echo "... (showing first 5 entries, total: $count_ipv4)"
        else
            echo "Set: $set_name_ipv4 (IPv4, not found)"
        fi
        # nftables IPv6 set
        if [ "$IPV6_ENABLED" -eq 1 ]; then
            if sudo nft list set ip6 filter "$set_name_ipv6" >/dev/null 2>&1; then
                local count_ipv6=$(sudo nft list set ip6 filter "$set_name_ipv6" | grep -E '^[[:space:]]+[0-9a-fA-F]' | wc -l)
                total_entries=$((total_entries + count_ipv6))
                echo "Set: $set_name_ipv6 (IPv6)"
                echo "Entries: $count_ipv6"
                echo "Sample Entries (up to 5):"
                sudo nft list set ip6 filter "$set_name_ipv6" | grep -E '^[[:space:]]+[0-9a-fA-F]' | head -n 5 || echo "(None)"
                [ $count_ipv6 -gt 5 ] && echo "... (showing first 5 entries, total: $count_ipv6)"
            else
                echo "Set: $set_name_ipv6 (IPv6, not found)"
            fi
        else
            echo "Set: $set_name_ipv6 (IPv6, disabled)"
        fi
    fi

    # iptables/nftables rules
    echo -e "\n--- Firewall Rules ---"
    if [ "$FIREWALL_BACKEND" = "iptables" ]; then
        # iptables rules
        if sudo iptables -L "$chain" -v -n >/dev/null 2>&1; then
            echo "Chain: $chain (IPv4)"
            sudo iptables -L "$chain" -v -n --line-numbers | grep -E "match-set $set_name_ipv4|Chain $chain" || echo "(No blocklist rules)"
        else
            echo "Chain: $chain (IPv4, not found)"
        fi
        # ip6tables rules
        if [ "$IPV6_ENABLED" -eq 1 ]; then
            if sudo ip6tables -L "$chain" -v -n >/dev/null 2>&1; then
                echo "Chain: $chain (IPv6)"
                sudo ip6tables -L "$chain" -v -n --line-numbers | grep -E "match-set $set_name_ipv6|Chain $chain" || echo "(No blocklist rules)"
            else
                echo "Chain: $chain (IPv6, not found)"
            fi
        else
            echo "Chain: $chain (IPv6, disabled)"
        fi
    else
        # nftables IPv4 rules
        if sudo nft list chain ip filter "$chain" >/dev/null 2>&1; then
            echo "Chain: $chain (IPv4)"
            sudo nft list chain ip filter "$chain" | grep -E "set $set_name_ipv4|chain $chain" || echo "(No blocklist rules)"
        else
            echo "Chain: $chain (IPv4, not found)"
        fi
        # nftables IPv6 rules
        if [ "$IPV6_ENABLED" -eq 1 ]; then
            if sudo nft list chain ip6 filter "$chain" >/dev/null 2>&1; then
                echo "Chain: $chain (IPv6)"
                sudo nft list chain ip6 filter "$chain" | grep -E "set $set_name_ipv6|chain $chain" || echo "(No blocklist rules)"
            else
                echo "Chain: $chain (IPv6, not found)"
            fi
        else
            echo "Chain: $chain (IPv6, disabled)"
        fi
    fi

    # Summary
    echo -e "\n--- Summary ---"
    echo "Total Entries: $total_entries"
    echo "Firewall Backend: $FIREWALL_BACKEND"
    echo "IPv6 Processing: $( [ "$IPV6_ENABLED" -eq 1 ] && echo "Enabled" || echo "Disabled" )"

    echo -e "\n=== End of Status ==="
    # Log the status output if logging is enabled
    if [ "$LOGGING_ENABLED" -eq 1 ]; then
        echo "Displayed status at $(date)" >> "$LOG_FILE"
    fi
}

# Main script

# Store original arguments for sudo re-launch
ORIGINAL_ARGS=("$@")
ORIGINAL_HOME="$HOME"

# Initialize variables
DEBUG_MODE=0
VERBOSE_DEBUG=0
LOGGING_ENABLED=0
DRY_RUN=0
IPV6_ENABLED=0
NON_INTERACTIVE=0
IPSET_TEST=0
PURGE_ALL="n"
PURGE_ALL_CONFIRM="n"
PURGE="n"
UPDATE_README="n"

# Parse command-line arguments
while [ $# -gt 0 ]; do
    case "$1" in
        --help)
            show_help
            exit 0
            ;;
        --config)
            load_config
            manage_configs
            exit 0
            ;;
        --auth)
            load_config
            manage_credentials
            exit 0
            ;;
        --config-dir=*)
            CONFIG_DIR_OVERRIDE="${1#*=}"
            shift
            ;;
        --purge)
            load_config
            PURGE="y"
            shift
            ;;
        --purge-all)
            load_config
            PURGE_ALL="y"
            shift
            # Check for -y/-Y
            if [ "$1" = "-y" ] || [ "$1" = "-Y" ]; then
                PURGE_ALL_CONFIRM="y"
                shift
            fi
            ;;
        --clear-rules)
            load_config
            clear_rules
            exit 0
            ;;
        --apply-rules)
            load_config
            check_sudo
            apply_rule inet "$IPSET_NAME"
            [ "$IPV6_ENABLED" -eq 1 ] && apply_rule inet6 "${IPSET_NAME}_v6"
            echo "Blocklist rules reapplied" >&2
            exit 0
            ;;
        --update-readme)
            load_config
            update_readme
            exit 0
            ;;
        --update-configfile)
            load_config
            update_configfile
            exit 0
            ;;
        --debug-level=*)
            DEBUG_LEVEL="${1#*=}"
            if [ "$DEBUG_LEVEL" -eq 1 ]; then
                DEBUG_MODE=1
                VERBOSE_DEBUG=0
                set +x
            elif [ "$DEBUG_LEVEL" -eq 2 ]; then
                DEBUG_MODE=1
                VERBOSE_DEBUG=1
                set -x
            else
                echo "Error: Invalid debug level (1 or 2)" >&2
                exit 1
            fi
            shift
            ;;
        --debug)
            DEBUG_MODE=1
            VERBOSE_DEBUG=0
            set +x
            shift
            ;;
        --verbosedebug)
            DEBUG_MODE=1
            VERBOSE_DEBUG=1
            set -x
            shift
            ;;
        --log)
            LOGGING_ENABLED=1
            shift
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        --ipv6)
            IPV6_ENABLED=1
            shift
            ;;
        --no-ipv4-merge)
            NO_IPV4_MERGE=y
            shift
            ;;
        --no-ipv6-merge)
            NO_IPV6_MERGE=y
            shift
            ;;
        --backend=*)
            FIREWALL_BACKEND="${1#*=}"
            if [[ ! "$FIREWALL_BACKEND" =~ ^(iptables|nftables)$ ]]; then
                echo "Error: Backend must be 'iptables' or 'nftables'" >&2
                exit 1
            fi
            shift
            ;;
        --non-interactive)
            NON_INTERACTIVE=1
            shift
            ;;
        --ipset-test)
            IPSET_TEST=1
            shift
            ;;
            --status)
            load_config
            show_status
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            show_help
            exit 1
            ;;
    esac
done

# Enforce allowed switches for --purge-all
if [ "$PURGE_ALL" = "y" ]; then
    for arg in "${ORIGINAL_ARGS[@]}"; do
        case "$arg" in
            --purge-all|-y|-Y|--debug|--verbosedebug|--debug-level=1|--debug-level=2|--log|--config-dir=*)
                ;;
            *)
                echo "Error: --purge-all only allows --debug, --verbosedebug, --debug-level=1|2, --log, and --config-dir" >&2
                exit 1
                ;;
        esac
    done
fi

# Enforce allowed switches for --purge
if [ "$PURGE" = "y" ]; then
    for arg in "${ORIGINAL_ARGS[@]}"; do
        case "$arg" in
            --purge|--debug|--verbosedebug|--debug-level=1|--debug-level=2|--log|--config-dir=*)
                ;;
            *)
                echo "Error: --purge only allows --debug, --verbosedebug, --debug-level=1|2, --log, and --config-dir" >&2
                exit 1
                ;;
        esac
    done
fi

# Load configuration
load_config
echo "CONFIG_DIR=$CONFIG_DIR" >&2

# Prevent concurrent runs
LOCK_DIR="$CONFIG_DIR/blocklist.lock.d"
echo "LOCK_DIR=$LOCK_DIR" >&2
if [ -z "$CONFIG_DIR" ] || [ ! -d "$CONFIG_DIR" ] || [ ! -w "$CONFIG_DIR" ]; then
    echo "Error: CONFIG_DIR ($CONFIG_DIR) is unset, does not exist, or is not writable" >&2
    exit 1
fi
if [ -d "$LOCK_DIR" ]; then
    echo "Warning: Stale lock directory $LOCK_DIR found; attempting to remove it" >&2
    rm -f "$LOCK_DIR/pid" 2>/dev/null
    if rmdir "$LOCK_DIR" 2>/dev/null; then
        [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Removed stale lock directory $LOCK_DIR" >&2
    else
        echo "Error: Cannot remove stale lock directory $LOCK_DIR; contents:" >&2
        ls -l "$LOCK_DIR" >&2
        echo "Error: Another instance may be running or directory is non-empty" >&2
        exit 1
    fi
fi
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
    echo "Error: Another instance is running or lock directory creation failed" >&2
    exit 1
fi
echo $$ > "$LOCK_DIR/pid"
[ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Created lock directory $LOCK_DIR with PID $$" >&2
trap 'cleanup' EXIT INT TERM

# Set up logging
if [ "$LOGGING_ENABLED" -eq 1 ]; then
    # Skip logging for commands that exit immediately
    case "${ORIGINAL_ARGS[*]}" in
        *--help*|*--config*|*--auth*|*--purge*|*--clear-rules*|*--apply-rules*|*--ipset-test*|*--update-readme*|*--update-configfile*)
            [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Skipping log file creation for ${ORIGINAL_ARGS[*]}" >&2
            ;;
        *)
            if ! touch "$LOG_FILE" 2>/dev/null; then
                echo "Error: Cannot write to $LOG_FILE" >&2
                exit 1
            fi
            chmod 600 "$LOG_FILE"
            # Create backup of existing log file
            if [ -f "$LOG_FILE" ]; then
                cp -f "$LOG_FILE" "${LOG_FILE}.bak" && chmod 600 "${LOG_FILE}.bak" || {
                    echo "Warning: Failed to create or set permissions for backup of $LOG_FILE to ${LOG_FILE}.bak" >&2
                }
                [ "$DEBUG_MODE" -eq 1 ] && echo "DEBUG: Created backup of $LOG_FILE to ${LOG_FILE}.bak" >&2
            fi
            # Warn if output is redirected
            if [ ! -t 1 ]; then
                echo "Warning: Output is already redirected (e.g., to a file); also logging to $LOG_FILE. Ctrl+C to cancel if undesired." >&2
            fi
            exec > >(tee -a "$LOG_FILE") 2>&1
            echo "Logging to $LOG_FILE" >&2
            ;;
    esac
fi

# Handle --purge
if [ "$PURGE" = "y" ]; then
    purge_blocklist
    exit 0
fi

# Handle --purge-all
if [ "$PURGE_ALL" = "y" ]; then
    purge_all "$PURGE_ALL_CONFIRM"
    exit 0
fi

# Ensure root privileges
check_sudo

# Set up temporary files
setup_temp_files

# Run syntax check if in debug mode
if [ "$DEBUG_MODE" -eq 1 ]; then
    if bash -n "$0"; then
        echo "Syntax check passed" >&2
    else
        echo "Syntax check failed" >&2
        exit 1
    fi
fi

# Verify iptables chain in interactive mode
if [ "$FIREWALL_BACKEND" = "iptables" ] && [ "$NON_INTERACTIVE" -eq 0 ]; then
    if ! sudo iptables -L "$IPTABLES_CHAIN" >/dev/null 2>&1; then
        echo "Warning: Chain $IPTABLES_CHAIN does not exist in iptables" >&2
        read -p "Continue anyway? (y/N): " continue_iptables </dev/tty
        if [[ ! "$continue_iptables" =~ ^[Yy]$ ]]; then
            echo "Aborted due to missing iptables chain" >&2
            exit 1
        fi
    fi
fi

# Update blocklist
update_blocklist "$DRY_RUN"

exit 0
