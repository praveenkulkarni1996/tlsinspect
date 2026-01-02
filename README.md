# TLS Inspect

A command-line tool for inspecting TLS/SSL certificates and connections.

## Installation

### Prerequisites

- Rust (latest stable version recommended)

### Building from Source

```bash
git clone https://github.com/praveenkulkarni1996/tlsinspect.git
cd tlsinspect
cargo build --release
```

The binary will be available at `target/release/tlsinspect`.

## Usage

```bash
tlsinspect [OPTIONS] <HOST>
```

### Options

- `<HOST>`: The hostname for SNI and validation (e.g., www.google.com)
- `--ip <IP>`: Optional specific IP to connect to (overrides DNS resolution)
- `--port <PORT>`: Port to connect to (default: 443)

## Examples

```bash
# Inspect a certificate from a domain
tlsinspect example.com

# Connect to a specific IP while using example.com for SNI
tlsinspect example.com --ip 93.184.216.34

# Connect to a non-standard port
tlsinspect example.com --port 8443
```

## Features

- Retrieve and display TLS certificate information
- Inspect certificate chains (leaf and intermediate certificates)
- Display certificate subject, algorithm, and serial number
- Support for custom IP and port connections
- SNI (Server Name Indication) support

## Dependencies

- [clap](https://crates.io/crates/clap) - Command line argument parser
- [rustls](https://crates.io/crates/rustls) - TLS library
- [tokio](https://crates.io/crates/tokio) - Async runtime
- [tokio-rustls](https://crates.io/crates/tokio-rustls) - TLS connector for tokio
- [webpki-roots](https://crates.io/crates/webpki-roots) - Web PKI root certificates
- [x509-parser](https://crates.io/crates/x509-parser) - X.509 certificate parser

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.