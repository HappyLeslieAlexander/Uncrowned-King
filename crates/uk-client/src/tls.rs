//! TLS helpers for the client carrier.

use std::{fs::File, io::BufReader};

use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, ServerName},
};
use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector, client::TlsStream};
use uk_auth::EXPORTER_LABEL;

/// Builds a TLS 1.3-only client connector.
pub fn connector(
    ca_cert_path: &str,
) -> Result<TlsConnector, Box<dyn std::error::Error + Send + Sync>> {
    let mut roots = RootCertStore::empty();
    for cert in load_certs(ca_cert_path)? {
        roots.add(cert)?;
    }
    let mut config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"uk/1".to_vec()];
    config.enable_early_data = false;
    Ok(TlsConnector::from(std::sync::Arc::new(config)))
}

/// Converts a configured server name into a rustls server name.
pub fn server_name(
    value: String,
) -> Result<ServerName<'static>, Box<dyn std::error::Error + Send + Sync>> {
    Ok(ServerName::try_from(value)?)
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
) -> Result<Vec<CertificateDer<'static>>, Box<dyn std::error::Error + Send + Sync>> {
    let mut reader = BufReader::new(File::open(path)?);
    let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    Ok(certs)
}
