#!/bin/bash
# Canary VPS claude-opus-gateway-rs : toolchain + build release + install + demarrage.
# Idempotent. Aucune modification du service prod astra-gateway.service.
set -euo pipefail
export HOME=/home/juliann
export PATH="$HOME/.cargo/bin:$PATH"
BUILD=/home/juliann/build/mcp-rust-migration

cargo --version
rustup component add rustfmt clippy 2>/dev/null || true
cd "$BUILD/claude-opus-gateway-rs"
echo "[canary] fmt/clippy/test…"
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
echo "[canary] build release…"
cargo build --release
echo "[canary] installation /opt/claude-opus-gateway-rs…"
sudo install -d -o astra-app -g astra-app -m 0755 /opt/claude-opus-gateway-rs
sudo install -m 0755 target/release/claude-opus-gateway-rs /opt/claude-opus-gateway-rs/claude-opus-gateway-rs
sudo install -m 0644 deploy/claude-opus-gateway-rs.service /etc/systemd/system/claude-opus-gateway-rs.service
sudo systemctl daemon-reload
echo "[canary] demarrage claude-opus-gateway-rs.service (:18996)…"
sudo systemctl enable --now claude-opus-gateway-rs.service
sleep 3
sudo systemctl is-active claude-opus-gateway-rs.service
curl -s http://127.0.0.1:18996/health; echo
curl -s http://127.0.0.1:18996/ready; echo
echo "[canary] OK"
