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

# Version 0.8: Added config file support, improved CIDR validation, enhanced download and error handling, added debug output

# Inspired from https://lowendspirit.com/discussion/7699/use-a-blacklist-of-bad-ips-on-your-linux-firewall-tutorial
# Credit to user itsdeadjim ( https://lowendspirit.com/profile/itsdeadjim )
# The original version of the script by itsdeadjim is referred to as 0.5 if it is uploaded

# Load credentials
if [ -f ~/.iblocklist.conf ]; then
    source ~/.iblocklist.conf
else
    echo "Config file ~/.iblocklist.conf not found."
    exit 1
fi

# URL of the IP list
URL="https://list.iblocklist.com/?list=cwworuawihqvocglcoss&fileformat=cidr&archiveformat=gz&username=${USERNAME}&pin=${PIN}"

# Temporary files
IP_LIST_RAW="/tmp/iplist.gz"
IP_LIST="/tmp/iplist.txt"
IPSET_RESTORE_FILE="/tmp/ipset_restore.txt"

# Clean up on exit
trap 'rm -f "$IP_LIST_RAW" "$IP_LIST" "$IPSET_RESTORE_FILE"' EXIT

# Download
if ! wget -nv --timeout=10 --tries=2 -O "$IP_LIST_RAW" "$URL"; then
    echo "Failed to download IP list from $URL"
    exit 1
fi
if [ ! -s "$IP_LIST_RAW" ]; then
    echo "Downloaded file is empty or invalid"
    exit 1
fi

# Verify gzip
if ! file "$IP_LIST_RAW" | grep -q "gzip compressed data"; then
    echo "Downloaded file is not a valid gzip archive"
    exit 1
fi

# Decompress
if ! gunzip -c "$IP_LIST_RAW" > "$IP_LIST"; then
    echo "Failed to decompress $IP_LIST_RAW"
    exit 1
fi
if [ ! -s "$IP_LIST" ]; then
    echo "Decompressed file is empty or invalid"
    exit 1
fi

# Debug
echo "First 5 lines of $IP_LIST:"
head -n 5 "$IP_LIST"
echo "Total valid CIDRs:"
total_cidr=$(grep -cE '^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$' "$IP_LIST")
echo "$total_cidr"
echo "Duplicate CIDRs:"
dupes=$(awk '/^([0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]{1,2}$/ {print $1}' "$IP_LIST" | sort -n -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4 | uniq -d | wc -l)
echo "$dupes"
echo "------------------------"

# Clean up existing ipset and iptables rule
sudo iptables -D INPUT -m set --match-set blacklist src -j DROP 2>/dev/null
sudo ipset destroy blacklist 2>/dev/null

# Create ipset
if ! sudo ipset create blacklist hash:net hashsize 65536; then
    echo "Failed to create ipset 'blacklist'"
    exit 1
fi

# Prepare ipset restore file
echo "flush blacklist" > "$IPSET_RESTORE_FILE"
awk '/^([0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]{1,2}$/ {
    split($1, a, "/");
    ip = a[1];
    mask = a[2];
    if (mask >= 1 && mask <= 32) {
        print "add blacklist " $1
    }
}' "$IP_LIST" | sort -n -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4 | uniq >> "$IPSET_RESTORE_FILE"

# Apply ipset restore
echo "Applying ipset restore ($((total_cidr - dupes)) unique entries)"
if ! sudo ipset restore < "$IPSET_RESTORE_FILE"; then
    echo "Failed to apply ipset restore"
    exit 1
fi

# Verify
added=$(sudo ipset list blacklist | grep -c '[0-9]\.[0-9]')
echo "Added $added entries to blacklist"
if [ "$added" -lt 40000 ]; then
    echo "Warning: Added fewer entries than expected (<40000)"
fi

# Apply iptables rule
if ! sudo iptables -C INPUT -m set --match-set blacklist src -j DROP 2>/dev/null; then
    if ! sudo iptables -I INPUT -m set --match-set blacklist src -j DROP; then
        echo "Failed to apply iptables rule"
        exit 1
    fi
fi

echo "Blocklist applied successfully"
