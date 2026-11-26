#!/usr/bin/env bash
# Supply-chain checks with the same narrowly scoped exceptions documented in deny.toml.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo audit \
  --ignore RUSTSEC-2023-0071 \
  --ignore RUSTSEC-2026-0387 \
  --ignore RUSTSEC-2026-0124 \
  --ignore RUSTSEC-2026-0207 \
  --ignore RUSTSEC-2026-0208 \
  --ignore RUSTSEC-2026-0209 \
  --ignore RUSTSEC-2026-0211 \
  --ignore RUSTSEC-2026-0212 \
  --ignore RUSTSEC-2026-0330 \
  --ignore RUSTSEC-2026-0331
cargo deny --locked check
