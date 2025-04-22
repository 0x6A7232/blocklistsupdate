#!/bin/bash

# Copied from https://lowendspirit.com/discussion/7699/use-a-blacklist-of-bad-ips-on-your-linux-firewall-tutorial
# Credit to user itsdeadjim ( https://lowendspirit.com/profile/itsdeadjim )
# Version 0.5: The OG

# URL of the IP list, use whatever you like
URL="http://abuse.myip.cam/allips.txt"

# Temporary file where the IP list will be stored
IP_LIST="/tmp/iplist.txt"

# Temporary file for ipset restore commands
IPSET_RESTORE_FILE="/tmp/ipset_restore.txt"

# Download the latest IP list
if ! wget --compression=gzip -nv -O $IP_LIST $URL; then
    echo "Failed to download IP list from $URL"
    exit 1
fi

# Prepare ipset restore file
echo "create blacklist hash:ip maxelem 200000 -exist" > $IPSET_RESTORE_FILE
echo "flush blacklist" >> $IPSET_RESTORE_FILE

# Append add commands to the restore file, make sure it looks like an ipv4 
grep -P '^([0-9]{1,3}\.){3}[0-9]{1,3}$' "$IP_LIST" | while IFS= read -r ip; do
    echo "add blacklist $ip" >> $IPSET_RESTORE_FILE
done

# Apply ipset changes
ipset restore < $IPSET_RESTORE_FILE

# Check if the iptables rule exists, if not, add it
if ! iptables -C INPUT -m set --match-set blacklist src -j DROP 2>/dev/null; then
    iptables -I INPUT -m set --match-set blacklist src -j DROP
fi
