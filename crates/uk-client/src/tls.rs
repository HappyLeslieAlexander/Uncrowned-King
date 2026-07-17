//! TLS helpers for the client carrier.

use std::fs;

use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, ServerName, pem::PemObject},
};
use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector, client::TlsStream};
use uk_auth::EXPORTER_LABEL;
use uk_proto::ALPN_PROTOCOL;

type TlsError = Box<dyn std::error::Error + Send + Sync>;

/// Builds a TLS 1.3-only rustls client config with the UK ALPN and 0-RTT
/// disabled, trusting only the configured CA. Shared by the TLS/TCP and QUIC
/// client carriers.
pub fn client_config(ca_cert_path: &str) -> Result<ClientConfig, TlsError> {
    let mut roots = RootCertStore::empty();
    for cert in load_certs(ca_cert_path)? {
        roots.add(cert)?;
    }
    let mut config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN_PROTOCOL.to_vec()];
    config.enable_early_data = false;
    Ok(config)
}

/// Builds a TLS 1.3-only client connector.
pub fn connector(ca_cert_path: &str) -> Result<TlsConnector, TlsError> {
    Ok(TlsConnector::from(std::sync::Arc::new(client_config(
        ca_cert_path,
    )?)))
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
    let pem =
        fs::read(path).map_err(|err| format!("failed to open CA certificate {path}: {err}"))?;
    let certs = CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("invalid CA certificate {path}: {err}"))?;
    if certs.is_empty() {
        Err(format!("missing CA certificate in {path}").into())
    } else {
        Ok(certs)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

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

    #[test]
    fn rejects_empty_ca_bundle() {
        let path = temp_file("empty-ca", b"");

        assert!(load_certs(&path).is_err());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn missing_ca_error_includes_path() {
        let path = temp_missing_file("missing-ca");

        let error = load_certs(&path).unwrap_err().to_string();

        assert!(error.contains(&path));
    }

    fn temp_file(name: &str, contents: &[u8]) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("uk-client-tls-{name}-{now}.pem"));
        fs::write(&path, contents).unwrap();
        path.to_string_lossy().into_owned()
    }

    fn temp_missing_file(name: &str) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir()
            .join(format!("uk-client-tls-{name}-{now}.pem"))
            .to_string_lossy()
            .into_owned()
    }
}
