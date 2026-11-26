FROM rust:1.100.0-slim-trixie@sha256:3b199fd6db7d709274df56565b8f4003f9e30d7bfcff9d53148c86053b7855e2 AS build
RUN apt-get update && apt-get install -y --no-install-recommends clang libclang-dev libudev-dev linux-libc-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY assets ./assets
RUN cargo build --locked --release

FROM debian:trixie-slim@sha256:8aa5a7bf5a1955bddbe7d74fcdd0b91ab30e74362a8b73af672b0481b35b44a0 AS runtime
LABEL org.opencontainers.image.source="https://github.com/adrianchifor/shomei" \
      org.opencontainers.image.url="https://github.com/adrianchifor/shomei" \
      org.opencontainers.image.title="Shomei" \
      org.opencontainers.image.description="Authentication proxy backed by hardware-attested YubiKeys"
RUN apt-get update && apt-get install -y --no-install-recommends libudev1 \
    && rm -rf /var/lib/apt/lists/* \
    && install -d -m 0700 -o 10001 -g 10001 /var/lib/shomei
USER 10001:10001
EXPOSE 8443 9443
ENTRYPOINT ["/usr/local/bin/shomei"]
CMD ["/etc/shomei/shomei.toml"]

FROM runtime AS release
ARG TARGETARCH
COPY --chmod=0755 dist/shomei-linux-${TARGETARCH} /usr/local/bin/shomei

FROM runtime AS local
COPY --from=build /build/target/release/shomei /usr/local/bin/shomei
