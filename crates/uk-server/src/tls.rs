//! TLS helpers for the server carrier.

use std::{fs::File, io::BufReader};

use rustls::{ServerConfig, pki_types::PrivateKeyDer};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use uk_auth::EXPORTER_LABEL;

/// Builds a TLS 1.3-only server config.
pub fn server_config(
    cert_path: &str,
    key_path: &str,
) -> Result<ServerConfig, Box<dyn std::error::Error + Send + Sync>> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;
    let mut config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    config.alpn_protocols = vec![b"uk/1".to_vec()];
    config.max_early_data_size = 0;
    Ok(config)
}

/// Exports the UK auth channel binding.
pub fn exporter(
    stream: &TlsStream<TcpStream>,
) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    let mut out = [0_u8; 32];
    stream
        .get_ref()
        .1
        .export_keying_material(&mut out, EXPORTER_LABEL, None)?;
    Ok(out)
}

fn load_certs(
    path: &str,
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, Box<dyn std::error::Error + Send + Sync>>
{
    let mut reader = BufReader::new(File::open(path)?);
    let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    Ok(certs)
}

fn load_private_key(
    path: &str,
) -> Result<PrivateKeyDer<'static>, Box<dyn std::error::Error + Send + Sync>> {
    let mut reader = BufReader::new(File::open(path)?);
    rustls_pemfile::private_key(&mut reader)?.ok_or_else(|| "missing private key".into())
}
