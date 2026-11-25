FROM rust:1.95.0-slim-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY assets ./assets
RUN cargo build --locked --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && install -d -m 0700 -o 10001 -g 10001 /var/lib/shomei
COPY --from=build /build/target/release/shomei /usr/local/bin/shomei
USER 10001:10001
EXPOSE 8443 9443
ENTRYPOINT ["/usr/local/bin/shomei"]
CMD ["/etc/shomei/shomei.toml"]
