#!/bin/bash

# Step 1: set ulimit! If you don't, the *nix default is 1024, which limits the speed of testing
ulimit -n 50000

# Step 2: Test the "known-endpoints.txt" URL file
cat ./known-endpoints.txt | shuf | zgrab2 http --custom-headers-names='Upgrade,Sec-WebSocket-Key,Sec-WebSocket-Version,Connection' --custom-headers-values='websocket,dXP3jD9Ipw0B2EmWrMDTEw==,13,Upgrade' --remove-accept-header --dynamic-origin --use-https --port 443 --max-redirects 10 --retry-https --cipher-suite portable -t 10 | jq '.data.http.result.response.status_code,.domain' | grep -A 1 -E --line-buffered '^101' | tee -a STEWS-discovery-output.txt
