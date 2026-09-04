FROM rust:alpine AS builder

RUN apk add --no-cache musl-dev
WORKDIR /usr/src/cause
COPY Cargo.toml ./
COPY Cargo.lock ./
COPY src ./src
RUN cargo build --release


FROM alpine:latest

RUN addgroup -g 1000 cause && adduser -u 1000 -G cause -D cause

# libgcc is required by some rust crates even on alpine
RUN apk add --no-cache ca-certificates bash libgcc

COPY --from=builder /usr/src/cause/target/release/cause /usr/local/bin/cause
# demo routes referenced by the shipped example config
COPY examples ./examples
COPY config.example.toml /etc/cause/cause.toml
RUN chmod -R a+r /etc/cause/ /examples/

USER cause
WORKDIR /
EXPOSE 3000

ENTRYPOINT ["cause"]
CMD ["--config", "/etc/cause/cause.toml", "--address", "0.0.0.0", "--port", "3000"]
