//! TLS helpers for the server carrier.

use std::{fs::File, io::BufReader};

use rustls::{ServerConfig, pki_types::PrivateKeyDer};
use tokio::net::TcpStream;
use tokio_rustls::server::TlsStream;
use uk_auth::EXPORTER_LABEL;
use uk_proto::ALPN_PROTOCOL;

type TlsError = Box<dyn std::error::Error + Send + Sync>;

/// Builds a TLS 1.3-only server config.
pub fn server_config(cert_path: &str, key_path: &str) -> Result<ServerConfig, TlsError> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;
    let mut config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    config.alpn_protocols = vec![ALPN_PROTOCOL.to_vec()];
    config.max_early_data_size = 0;
    Ok(config)
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

fn load_certs(path: &str) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, TlsError> {
    let mut reader = BufReader::new(File::open(path)?);
    let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        Err("missing certificate".into())
    } else {
        Ok(certs)
    }
}

fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>, TlsError> {
    let mut reader = BufReader::new(File::open(path)?);
    rustls_pemfile::private_key(&mut reader)?.ok_or_else(|| "missing private key".into())
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
    fn rejects_empty_cert_chain() {
        let path = temp_file("empty-cert", b"");

        assert!(load_certs(&path).is_err());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_empty_private_key_file() {
        let path = temp_file("empty-key", b"");

        assert!(load_private_key(&path).is_err());

        let _ = fs::remove_file(path);
    }

    fn temp_file(name: &str, contents: &[u8]) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("uk-server-tls-{name}-{now}.pem"));
        fs::write(&path, contents).unwrap();
        path.to_string_lossy().into_owned()
    }
}
