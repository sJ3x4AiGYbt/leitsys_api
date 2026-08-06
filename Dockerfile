# syntax=docker/dockerfile:1

FROM rust:1-slim-bookworm AS chef
RUN cargo install cargo-chef --locked
WORKDIR /app

# ─── planner 
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ─── builder
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release
RUN mv target/release/leitsys_api /app/leitsys_api

# ─── prod
FROM debian:bookworm-slim AS prod
RUN useradd -m -u 1000 appuser
WORKDIR /app
COPY --from=builder /app/leitsys_api /app/leitsys_api
RUN mkdir -p /app/data && chown -R appuser:appuser /app
USER appuser
ENV DATABASE_URL=sqlite:/app/data/leitsys.db
EXPOSE 3000
CMD ["/app/leitsys_api"]

# ─── dev
FROM chef AS dev
RUN cargo install cargo-watch --locked
WORKDIR /app
EXPOSE 3000
CMD ["cargo", "watch", "-x", "run"]