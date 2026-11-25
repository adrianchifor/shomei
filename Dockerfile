FROM rust:1.100.0-slim-trixie@sha256:3b199fd6db7d709274df56565b8f4003f9e30d7bfcff9d53148c86053b7855e2 AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY assets ./assets
RUN cargo build --locked --release

FROM debian:trixie-slim@sha256:8aa5a7bf5a1955bddbe7d74fcdd0b91ab30e74362a8b73af672b0481b35b44a0
RUN install -d -m 0700 -o 10001 -g 10001 /var/lib/shomei
COPY --from=build /build/target/release/shomei /usr/local/bin/shomei
USER 10001:10001
EXPOSE 8443 9443
ENTRYPOINT ["/usr/local/bin/shomei"]
CMD ["/etc/shomei/shomei.toml"]
