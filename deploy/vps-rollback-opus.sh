#!/bin/bash
# Rollback canary astra : stoppe le canary, verifie aucune prod astra existante (cutover 15/09).
# Aucune modification du service prod (jamais pointe vers le binaire Rust).
set -euo pipefail
sudo systemctl stop claude-opus-mcp.service || true
sudo systemctl is-active astra-gateway.service
curl -s http://127.0.0.1:8796/health; echo
echo "[rollback] aucune prod astra existante (cutover 15/09), canary stoppe"
