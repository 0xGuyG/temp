#!/bin/bash

# Define the old and new Wazuh server IP addresses
OLD_IP="3.72.244.230"
NEW_IP="34.247.200.15"

# Path to the ossec.conf file
OSSEC_CONF_PATH="/var/ossec/etc/ossec.conf"

# Stop Wazuh agent before making changes
service wazuh-agent stop

# Check if the ossec.conf file exists
if [ -f "$OSSEC_CONF_PATH" ]; then
    # Use sed to find and replace the old server IP with the new one
    sed -i "s/<address>$OLD_IP<\/address>/<address>$NEW_IP<\/address>/g" "$OSSEC_CONF_PATH"
    echo "Server IP changed from $OLD_IP to $NEW_IP in $OSSEC_CONF_PATH."
else
    echo "The ossec.conf file does not exist at the specified path: $OSSEC_CONF_PATH."
fi

# Start Wazuh agent after making changes
systemctl restart wazuh-agent.service
