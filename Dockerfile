# Build the gateway with its locked dependency graph; no SSH credentials are needed.
FROM rust:1.98-bookworm AS build
WORKDIR /src
COPY . .
RUN apt-get update \
    && apt-get install -y --no-install-recommends zstd \
    && mkdir -p /etc/siros-verifier/circuits \
    && zstd -d -f /src/zkp/testdata/nymauth/mdoc-circuits.zst -o /etc/siros-verifier/circuits/nymauth-mdoc.bin \
    && cargo build --locked --release -p siros-verifier-service

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/siros-verifier-service /usr/local/bin/siros-verifier-service
COPY --from=build /etc/siros-verifier/circuits/nymauth-mdoc.bin /etc/siros-verifier/circuits/nymauth-mdoc.bin
ENV TUNNELBANA_BIND=0.0.0.0:9001
EXPOSE 9001
ENTRYPOINT ["/usr/local/bin/siros-verifier-service"]
