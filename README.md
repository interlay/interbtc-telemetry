# PolkaBTC Telemetry

Backend service for monitoring client uptime and writing metrics to PostgreSQL.

## Getting Started

Run postgres in docker or locally - required by `sqlx` for compile-time syntax verification.

```shell
docker run --rm --name postgres \
    -p 5432:5432 \
    -e POSTGRES_USER=postgres \
    -e POSTGRES_PASSWORD=password \
    postgres:11
```

Install `sqlx-cli` and run migrations.

```shell
# install sqlx client
cargo install sqlx-cli

# create the database
sqlx db create

# run the migrations
sqlx migrate run
```

Start the backend server:

```shell
cargo run --bin http-server
```

Or run the tests:

```shell
cargo test
```