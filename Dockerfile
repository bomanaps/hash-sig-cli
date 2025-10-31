FROM rust:1.87 AS builder

WORKDIR /usr/src/hash-sig-cli

COPY Cargo.toml ./

# Create a new empty shell project to cache dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build the dependencies
RUN cargo build --release
RUN rm -f target/release/deps/hash_sig_cli*

# Copy the source code
COPY . .

# Build the actual application
RUN cargo build --release

# Use a smaller base image for the final image
FROM debian:buster-slim

# Copy the compiled binary from the builder stage
COPY --from=builder /usr/src/hash-sig-cli/target/release/hashsig /usr/local/bin/hashsig

# Set the entry point for the container
ENTRYPOINT ["hashsig"]