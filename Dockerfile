FROM messense/rust-musl-cross:x86_64-musl AS builder
WORKDIR /app
COPY . .
RUN cargo build --release --target x86_64-unknown-linux-musl

FROM scratch
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/deploy-test /deploy-test
EXPOSE 3000
ENTRYPOINT ["/deploy-test"]

