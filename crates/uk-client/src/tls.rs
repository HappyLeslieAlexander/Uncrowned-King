//! TLS helpers for the client carrier.

use std::{fs::File, io::BufReader};

use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, ServerName},
};
use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector, client::TlsStream};
use uk_auth::EXPORTER_LABEL;
use uk_proto::ALPN_PROTOCOL;

type TlsError = Box<dyn std::error::Error + Send + Sync>;

/// Builds a TLS 1.3-only client connector.
pub fn connector(ca_cert_path: &str) -> Result<TlsConnector, TlsError> {
    let mut roots = RootCertStore::empty();
    for cert in load_certs(ca_cert_path)? {
        roots.add(cert)?;
    }
    let mut config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN_PROTOCOL.to_vec()];
    config.enable_early_data = false;
    Ok(TlsConnector::from(std::sync::Arc::new(config)))
}

/// Converts a configured server name into a rustls server name.
pub fn server_name(value: String) -> Result<ServerName<'static>, TlsError> {
    Ok(ServerName::try_from(value)?)
}

/// Verifies that the TLS handshake negotiated the UK ALPN protocol.
pub fn verify_alpn(stream: &TlsStream<TcpStream>) -> Result<(), TlsError> {
    ensure_alpn(stream.get_ref().1.alpn_protocol())
}

/// Exports the UK auth channel binding.
pub fn exporter(stream: &TlsStream<TcpStream>) -> Result<[u8; 32], TlsError> {
    let mut out = [0_u8; 32];
    stream
        .get_ref()
        .1
        .export_keying_material(&mut out, EXPORTER_LABEL, None)?;
    Ok(out)
}

fn ensure_alpn(protocol: Option<&[u8]>) -> Result<(), TlsError> {
    if protocol == Some(ALPN_PROTOCOL) {
        Ok(())
    } else {
        Err("UK ALPN protocol was not negotiated".into())
    }
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let mut reader = BufReader::new(File::open(path)?);
    let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    Ok(certs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_uk_alpn() {
        assert!(ensure_alpn(Some(ALPN_PROTOCOL)).is_ok());
    }

    #[test]
    fn rejects_missing_alpn() {
        assert!(ensure_alpn(None).is_err());
    }

    #[test]
    fn rejects_wrong_alpn() {
        assert!(ensure_alpn(Some(b"h2")).is_err());
    }
}
