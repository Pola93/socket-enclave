# // Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# // SPDX-License-Identifier: MIT-0

#!/bin/sh

# Assign an IP address to local loopback, locally comment this out
ip addr add 127.0.0.1/32 dev lo
ip link set dev lo up

# Add a hosts record, pointing target site calls to local loopback
echo "127.0.0.1   kms.eu-central-1.amazonaws.com" >> /etc/hosts

touch /opt/app/libnsm.so

# Run traffic forwarder in background and start the server
cd /opt/app
python3 traffic_forwarder.py 127.0.0.1 443 3 8000 &
python3 server.py server 5005 6666
