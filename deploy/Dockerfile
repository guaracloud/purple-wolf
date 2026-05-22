# Build a fully static musl binary, ship it on scratch.
# Multi-arch: works on both linux/amd64 and linux/arm64 alpine images
# because the alpine rust toolchain targets the native musl triple.
FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY . .
RUN cargo build --release

FROM scratch
# Copy the native-arch musl binary — alpine builds straight into
# target/release/, no triple subdirectory.
COPY --from=build /src/target/release/purple-wolf /purple-wolf
COPY config/purple-wolf.toml /config/purple-wolf.toml
ENV PURPLE_WOLF_CONFIG=/config/purple-wolf.toml
EXPOSE 8080 9090
ENTRYPOINT ["/purple-wolf"]
