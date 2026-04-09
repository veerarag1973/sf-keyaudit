# ── Build stage ───────────────────────────────────────────────────────────────
FROM rust:1.75-slim AS builder

WORKDIR /app

# Install system dependencies required for native crates (openssl, bzip2).
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev \
        libbz2-dev \
        git \
    && rm -rf /var/lib/apt/lists/*

# Accept build metadata as build-time arguments so the version banner is correct.
ARG SF_BUILD_YEAR=2026
ARG SF_BUILD_NUMBER=docker
ENV SF_BUILD_YEAR=${SF_BUILD_YEAR} \
    SF_BUILD_NUMBER=${SF_BUILD_NUMBER}

# Cache dependency compilation separately from source builds.
COPY Cargo.toml Cargo.lock build.rs ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs \
    && cargo build --release 2>/dev/null || true \
    && rm -rf src

# Build the real binary.
COPY . .
RUN cargo build --release --locked

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

# git is required for --staged / --history / --since-commit modes.
# ca-certificates is required for HTTPS validation requests.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        git \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/sf-keyaudit /usr/local/bin/sf-keyaudit

# Run as a non-root user for least-privilege operation.
RUN useradd --uid 10000 --no-create-home --shell /sbin/nologin scanner
USER scanner

# Scan the mounted directory by default.
WORKDIR /scan

ENTRYPOINT ["sf-keyaudit"]
CMD ["."]
