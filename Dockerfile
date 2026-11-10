# Build the gateway with its locked dependency graph; no SSH credentials are needed.
# Alpine/musl end to end: the runtime image is Alpine, so the build stage
# compiles against musl too — a glibc binary would not run on the Alpine base.
FROM rust:1.98-alpine AS build
WORKDIR /src
COPY . .
RUN apk add --no-cache ca-certificates cmake g++ git make musl-dev perl zstd \
    && mkdir -p /etc/siros-verifier/circuits \
    && zstd -d -f /src/zkp/testdata/nymauth/mdoc-circuits.zst -o /etc/siros-verifier/circuits/nymauth-mdoc.bin \
    && cargo build --locked --release -p siros-verifier-service

FROM alpine:3.22
RUN apk add --no-cache ca-certificates curl \
    && addgroup -g 10001 -S siros \
    && adduser -u 10001 -G siros -S -H siros
COPY --from=build /src/target/release/siros-verifier-service /usr/local/bin/siros-verifier-service
COPY --from=build /etc/siros-verifier/circuits/nymauth-mdoc.bin /etc/siros-verifier/circuits/nymauth-mdoc.bin
ENV TUNNELBANA_BIND=0.0.0.0:9001
# Numeric UID/GID: the container runs unprivileged, and orchestrators can
# verify runAsNonRoot without name resolution. The service needs no
# writable path — flow state lives in the shared store, config and keys
# are mounted read-only — and 9001 is an unprivileged port.
USER 10001:10001
EXPOSE 9001
ENTRYPOINT ["/usr/local/bin/siros-verifier-service"]
