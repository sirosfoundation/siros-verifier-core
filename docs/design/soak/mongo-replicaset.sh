#!/usr/bin/env bash
# The MongoDB replica set for the HA soak (docs/design/SOAK.md): three local
# members on the host network, so a verifier run against it sees real
# elections, real failover, and real majority write concern — the properties
# the soak exercises.
#
#   docs/design/soak/mongo-replicaset.sh up        # three members + initiate
#   docs/design/soak/mongo-replicaset.sh stepdown  # force a primary failover
#   docs/design/soak/mongo-replicaset.sh teardown
set -euo pipefail

IMAGE=mongo:7.0
NAME_PREFIX=soak-mongo
PORTS=(27017 27018 27019)
URI="mongodb://127.0.0.1:27017,127.0.0.1:27018,127.0.0.1:27019/?replicaSet=soakrs"

mongosh_eval() {
  docker run --rm --network host "$IMAGE" mongosh --quiet "$1" --eval "$2"
}

up() {
  for port in "${PORTS[@]}"; do
    docker rm -f "$NAME_PREFIX-$port" >/dev/null 2>&1 || true
    docker run --rm -d --name "$NAME_PREFIX-$port" --network host \
      "$IMAGE" mongod --replSet soakrs --port "$port" --bind_ip 127.0.0.1 >/dev/null
  done
  sleep 3
  mongosh_eval "mongodb://127.0.0.1:27017" '
    try { rs.status() } catch (e) {
      try {
        rs.initiate({
          _id: "soakrs",
          members: [
            { _id: 0, host: "127.0.0.1:27017", priority: 2 },
            { _id: 1, host: "127.0.0.1:27018", priority: 1 },
            { _id: 2, host: "127.0.0.1:27019", priority: 1 },
          ],
        })
      } catch (already) { }
    }'
  for _ in $(seq 1 30); do
    primary=$(mongosh_eval "mongodb://127.0.0.1:27017" 'db.hello().primary' || true)
    if [ -n "$primary" ] && [ "$primary" != "UNKNOWN" ]; then
      echo "replica set up: primary $primary"
      echo "uri: $URI"
      return 0
    fi
    sleep 1
  done
  echo "replica set did not elect a primary" >&2
  exit 1
}

stepdown() {
  primary=$(mongosh_eval "mongodb://127.0.0.1:27017" 'db.hello().primary' || true)
  [ -n "$primary" ] || { echo "no primary found" >&2; exit 1; }
  port=${primary##*:}
  echo "stepping down $primary"
  # The step-down itself; the primary may already be gone from the
  # connection's view, so query the new primary on a fresh connection.
  mongosh_eval "mongodb://127.0.0.1:$port" 'rs.stepDown(15)' >/dev/null 2>&1 || true
  sleep 2
  new_primary=$(mongosh_eval "mongodb://127.0.0.1:27017" 'db.hello().primary' || true)
  echo "primary now: ${new_primary:-electing}"
}

teardown() {
  for port in "${PORTS[@]}"; do
    docker rm -f "$NAME_PREFIX-$port" >/dev/null 2>&1 || true
  done
  echo down
}

case "${1:-}" in
  up) up ;;
  stepdown) stepdown ;;
  teardown) teardown ;;
  *) echo "usage: $0 up|stepdown|teardown" >&2; exit 2 ;;
esac
