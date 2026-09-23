#!/bin/bash
# Verification canary astra : sante + fail-closed, aucune prod astra existante (cutover 15/09). Lecture seule.
set -u
export HOME=/home/juliann
echo "=== canary :18996 ==="
curl -s --max-time 5 http://127.0.0.1:18996/health; echo
curl -s --max-time 5 http://127.0.0.1:18996/ready; echo
curl -s -o /dev/null -w "POST /mcp sans auth -> %{http_code}\n" --max-time 5 \
  -X POST http://127.0.0.1:18996/mcp -H "content-type: application/json" -d '{}' || true
systemctl is-active claude-opus-gateway-rs.service
echo "=== aucune prod astra existante (cutover 15/09) ==="
curl -s --max-time 5 http://127.0.0.1:8796/health; echo
systemctl is-active astra-gateway.service astra-mcp.service
