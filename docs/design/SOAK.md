# The HA/overload soak

The operational rehearsal behind the testing release: the real service binary,
two replicas, a genuine three-member MongoDB replica set, and sustained
wallet-driven load past the admission budget — with a forced database
failover and a forced verifier kill in the middle. Plus the native leg: the
genuine Longfellow circuit and proof vector verified under sustained
concurrency in the same blocking-pool shape the service gives it.

This is a developer-only procedure and its tools are developer-only (they
live under `docs/design/`, per the repo's layout rule). Nothing here is a
production deployment profile: the PDP is a loopback stand-in returning a
fixed verdict, everything is plain HTTP on loopback, and the state key is a
throwaway.

## What the soak holds the service to

1. **Exactly-once completion.** A flow answered 200 completes once and is
   never delivered twice (the driver re-collects sampled flows and treats a
   second verified result as a violation).
2. **Any replica can complete any flow.** Flow state lives in the shared
   store: a connect failure on one replica is served by the other, mid-flow.
3. **Bounded failover.** A MongoDB primary step-down mid-load may produce
   store-unavailable answers (503); they must be retried and followed by
   resumed completions, never by hangs or duplicate deliveries.
4. **Admission holds under overload.** More concurrent presentations than
   `max_concurrent_verifications` queue, are served, and complete; nothing
   times out behind an unbounded pile.
5. **The native hot path is stable under sustained load.** The genuine
   Longfellow verification loop reports no verification changes, bounded
   latency drift, and bounded resident-memory growth.

## Tooling

- `soak/mongo-replicaset.sh` — three local MongoDB members on 127.0.0.1
  (27017-27019) with `up`, `stepdown` (forces a primary failover), and
  `teardown`.
- `soak/soak.toml` — the service configuration both replicas run: shared
  MongoDB storage, the loopback PDP stand-in, the SD-JWT PID query the driver
  presents against.
- `soak_driver` (cargo example of the service crate,
  `docs/design/examples/soak_driver.rs`) — a dev-only wallet-and-load
  harness. It issues one genuine SD-JWT PID credential and re-presents it
  nonce-bound for every flow, exactly as a real wallet re-presents its
  credential; it also serves the loopback go-trust stand-in. It drives the
  real HTTP surface a browser and wallet use: `POST /ui/start/qr`, the request
  object at `/vp/request/{id}`, the encrypted response at
  `/vp/response/{id}`, and collection at `/vp/complete`, carrying the state
  cookie.
- `soak_native` (cargo example of the zkp crate,
  `docs/design/examples/soak_native.rs`) — the genuine Longfellow vector
  (the same testdata the native vector tests pin) verified in a sustained
  loop across N concurrent workers, reporting throughput, latency
  percentiles, first-half-to-second-half median drift, and RSS growth. It
  refuses to start if the vector does not verify or if mutations are not
  refused.

## Procedure

All commands from the repository root. Release builds — debug measures
nothing.

```sh
# 0. Keys and secrets (throwaway, local only).
mkdir -p /tmp/opencode/soak-keys
openssl ecparam -name prime256v1 -genkey -noout \
  | openssl pkcs8 -topk8 -nocrypt -out /tmp/opencode/soak-keys/verifier.key
openssl req -new -x509 -key /tmp/opencode/soak-keys/verifier.key -days 2 \
  -subj "/CN=soak-verifier.local" \
  -addext "subjectAltName=DNS:soak-verifier.local" \
  -out /tmp/opencode/soak-keys/verifier.pem
export SIROS_VERIFIER_STATE_KEY=$(openssl rand -hex 32)

# 1. The three-member MongoDB replica set.
docs/design/soak/mongo-replicaset.sh up
export SIROS_VERIFIER_MONGODB_URI='mongodb://127.0.0.1:27017,127.0.0.1:27018,127.0.0.1:27019/?replicaSet=soakrs'

# 2. Two replicas of the real binary, one config, shared store.
cargo build --release -p siros-verifier-service
TUNNELBANA_BIND=127.0.0.1:9001 \
  target/release/siros-verifier-service docs/design/soak/soak.toml &
TUNNELBANA_BIND=127.0.0.1:9002 \
  target/release/siros-verifier-service docs/design/soak/soak.toml &

# 3. Sustained overload across both replicas (the driver also serves the
#    loopback PDP on 6001). Twice the admission budget in users, minutes of
#    load.
cargo run --release -p siros-verifier-service --example soak_driver -- \
  --replicas http://127.0.0.1:9001,http://127.0.0.1:9002 \
  --users 32 --duration 180 --pdp 127.0.0.1:6001

# 4. Mid-load failovers (in a second window, while the driver runs):
docs/design/soak/mongo-replicaset.sh stepdown
kill -9 <pid of the 9001 replica>   # then restart it with the same command

# 5. The native leg.
cargo run --release -p siros-verifier-zkp --example soak_native -- \
  --duration 120 --workers 8
```

The driver prints a progress line per interval and a summary with a PASS/FAIL
verdict against the invariants above (duplicate results zero, completions
resumed after the last connect failure). The native tool prints throughput,
latency percentiles, drift, and RSS, and fails if any verification result
changes under sustained load.

## Evidence from the local rehearsal

Recorded 2026-11-09, this repository at the merge of the soak PR, on the
development sandbox (16 GiB tmpfs, host-networked Docker, mongo:7.0, release
builds). Leg 1 ran two verifier replicas against a three-member replica set
(127.0.0.1:27017-27019), 32 driver users — twice the 16-slot admission
budget — for 180 seconds, with the primary stepped down at +45s
(127.0.0.1:27017 → 127.0.0.1:27018, a real election), replica 9001 killed
with SIGKILL at +75s and restarted at +90s.

### Leg 1 — HA/overload across two replicas and a three-member replica set

```
started:            87005
answered 200:       86999
replay (409):       4        # POSTs that hit the killed replica mid-connection:
                             # retried after failover, correctly refused as
                             # already received, then collected
store 503 retried:  0        # the 3-member election finished inside the
                             # write bound: not one store-unavailable answer
connect failovers:  12
completed:          86998
failed:             7        # all at the kill boundary
duplicate results:  0
completions resumed after the last connect failure: true
VERDICT: PASS
```

Sustained throughput was ~484 flows/second across the two replicas, every
flow a complete genuine SD-JWT presentation: nonce-bound KB-JWT and JWE
response, a trust evaluation, a majority write, and one-time collection.
Verifier resident memory after ~87k flows: 20-37 MiB per replica.

### Leg 2 — native Longfellow under sustained load

Genuine Longfellow circuit and proof vector, 8 concurrent workers (the
release record's hot-path numbers):

| Run | verifies | /s | refused | p50 | p95 | p99 | max | drift | RSS |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 120s | 1513 | 12.6 | 0 | 628 ms | 911 ms | 953 ms | 1021 ms | 53.9% | 86 → 270 MiB |
| 300s | 3653 | 12.2 | 0 | 662 ms | 921 ms | 980 ms | 1486 ms | 39.2% | 86 → 264 MiB |

The verdict-relevant readings: **no verification result changed under
sustained load** in either run, and **throughput held** (12.2/s over five
minutes vs 12.6/s over two). The 300s run did 2.4× the verifies of the 120s
run and ended at the SAME resident memory — the growth is a warmup plateau
(~265 MiB), not a per-verify leak. The first-half-to-second-half median
drift is the warmup transition: latency settles around a 660 ms median and
holds. Operationally, one native verify occupies a crypto slot for ~0.65 s,
so the default 16 slots bound native verification at roughly 24 verifies per
second per verifier before queueing — the budget the release record should
state.

## Notes and limits

- The PDP stand-in returns a fixed verdict; trust-evaluation latency under
  load is exercised by the conformance runs, not this soak.
- Credentials in the soak carry no status reference, so status-list fetching
  is not in this leg; it has its own bounded-client tests.
- The soak's wallet is genuine SD-JWT issuance and presentation per flow
  (nonce-bound), but the native leg cannot generate fresh per-session
  Longfellow proofs — the workspace is verify-only for native ZKP (no prover),
  and each proof binds its session transcript. The native leg therefore
  measures the verification hot path in isolation, which is the operational
  property the release record needs; per-session end-to-end native
  presentations are exercised by the conformance suite.
