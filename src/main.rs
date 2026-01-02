/// # TLS Inspect CLI
///
/// A command-line tool for inspecting TLS/SSL certificates and connections.
///
/// ## Usage
///
/// ```bash
/// tlsinspect [OPTIONS] <COMMAND>
/// ```
///
/// ## Examples
///
/// ```bash
/// # Inspect a certificate from a domain
/// tlsinspect inspect example.com
///
/// # Show certificate details with verbose output
/// tlsinspect inspect example.com --verbose
///
/// # Verify certificate chain
/// tlsinspect verify --cert path/to/cert.pem
///
/// # Check certificate expiration
/// tlsinspect check example.com --expiry
/// ```
///
/// ## Features
///
/// - Retrieve and display TLS certificate information
/// - Verify certificate chains and validity
/// - Check certificate expiration dates
/// - Inspect certificate extensions and attributes
/// - Support for multiple certificate formats
use clap::Parser;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use x509_parser::prelude::*;

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// The hostname for SNI and validation (e.g. www.google.com)
    host: String,

    /// Optional: Specific IP to connect to (overrides DNS resolution)
    #[arg(long)]
    ip: Option<String>,

    #[arg(short, long, default_value_t = 443)]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // 1. Setup TLS Config
    let root_store = {
        let mut store = RootCertStore::empty();
        store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        store
    };
    let config = Arc::new(
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    );
    let connector = TlsConnector::from(config);

    // 2. Determine Connection Target vs SNI Host
    // connect_addr is the physical IP/Host we dial
    // sni_host is the name we put in the TLS handshake
    let connect_addr = match &args.ip {
        Some(override_ip) => format!("{}:{}", override_ip, args.port),
        None => format!("{}:{}", args.host, args.port),
    };

    let sni_host = ServerName::try_from(args.host.as_str())
        .map_err(|_| "Invalid SNI hostname")?
        .to_owned();

    println!("Targeting: {}", connect_addr);
    println!("SNI Host:  {}", args.host);

    // 3. Connect to the physical IP
    let stream = TcpStream::connect(&connect_addr).await?;
    println!("TCP Connection established to {}", stream.peer_addr()?);

    // 4. Start TLS Handshake using the SNI name
    let tls_stream = connector.connect(sni_host, stream).await?;

    // 5. Inspect Chain
    let (_, session) = tls_stream.get_ref();
    let cert_chain = session.peer_certificates().ok_or("No certs found")?;

    for (i, cert) in cert_chain.iter().enumerate() {
        let label = if i == 0 { "Leaf" } else { "Intermediate" };
        let (_, x509) = X509Certificate::from_der(cert.as_ref())?;

        println!("[{}] {}", label, x509.subject());
        println!("   Issuer:    {}", x509.issuer());
        println!("   Valid from: {}", x509.validity().not_before);
        println!("   Valid to:   {}", x509.validity().not_after);
        println!("   Serial:    {}", x509.raw_serial_as_string());
        println!("   Algorithm: {}", x509.public_key().algorithm.algorithm);
    }

    Ok(())
}
