#!/usr/bin/env bash
# Supply-chain checks with the same narrowly scoped exceptions documented in deny.toml.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo audit \
  --ignore RUSTSEC-2023-0071 \
  --ignore RUSTSEC-2026-0387
cargo deny --locked check
