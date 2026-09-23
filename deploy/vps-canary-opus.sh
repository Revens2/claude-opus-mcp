#!/bin/bash
# Canary VPS claude-opus-mcp : toolchain + build release + install + demarrage.
# Idempotent. Aucune modification du service prod astra-gateway.service.
set -euo pipefail
export HOME=/home/juliann
export PATH="$HOME/.cargo/bin:$PATH"
BUILD=/home/juliann/build/mcp-rust-migration

cargo --version
rustup component add rustfmt clippy 2>/dev/null || true
cd "$BUILD/claude-opus-mcp"
echo "[canary] fmt/clippy/test…"
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
echo "[canary] build release…"
cargo build --release
echo "[canary] installation /opt/claude-opus-mcp…"
sudo install -d -o astra-app -g astra-app -m 0755 /opt/claude-opus-mcp
sudo install -m 0755 target/release/claude-opus-mcp /opt/claude-opus-mcp/claude-opus-mcp
sudo install -m 0644 deploy/claude-opus-mcp.service /etc/systemd/system/claude-opus-mcp.service
sudo systemctl daemon-reload
echo "[canary] demarrage claude-opus-mcp.service (:18996)…"
sudo systemctl enable --now claude-opus-mcp.service
sleep 3
sudo systemctl is-active claude-opus-mcp.service
curl -s http://127.0.0.1:18996/health; echo
curl -s http://127.0.0.1:18996/ready; echo
echo "[canary] OK"
