//! TLS helpers for the client carrier.

use std::{
    collections::HashMap,
    fs,
    sync::{Arc, LazyLock, Mutex, MutexGuard, PoisonError},
    time::Duration,
};

use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, ServerName, pem::PemObject},
};
use tokio::{net::TcpStream, task, time};
use tokio_rustls::{TlsConnector, client::TlsStream};
use uk_auth::EXPORTER_LABEL;
use uk_proto::ALPN_PROTOCOL;

type TlsError = Box<dyn std::error::Error + Send + Sync>;

/// Client configs already built from a CA bundle, keyed by the configured
/// `ca_cert_path`.
///
/// Building one reads and parses the CA file, which must not happen on a
/// runtime worker: the client would do it on every pooled reconnect and once
/// per QUIC endpoint attempt, so a stalled CA path (an automount or an NFS
/// mount) would block the worker rather than merely fail the dial.
///
/// The key is the path because `ca_cert_path` can change across SIGHUP
/// reloads. SIGHUP reload validation uses [`validate_ca_bundle`] or [`connector`],
/// which validate the CA file without mutating the cache. When a reload passes
/// compatibility checks, [`refresh_client_config`] atomically refreshes the entry,
/// so a CA rotated in place under an unchanged path is picked up only upon successful reload.
static CLIENT_CONFIGS: LazyLock<Mutex<HashMap<String, Arc<ClientConfig>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Upper bound for reading and parsing a CA bundle off the runtime.
///
/// A stalled CA path (automount, NFS) must fail the dial or reload within a
/// bounded time instead of parking the caller forever. The bound is
/// deliberately generous: it only needs to catch a wedged filesystem, not
/// slow-but-progressing reads.
pub const CA_LOAD_TIMEOUT: Duration = Duration::from_secs(10);

/// Returns the shared client config for `ca_cert_path`, reading and parsing
/// the CA bundle on a blocking thread only when it is not cached yet.
///
/// The blocking read is bounded by [`CA_LOAD_TIMEOUT`]. On timeout the caller
/// keeps the previously cached config (nothing is published); if the orphaned
/// read later completes, it publishes a config freshly read from disk — the
/// same value any subsequent load would produce — so no torn state can leak.
pub async fn shared_client_config(ca_cert_path: &str) -> Result<Arc<ClientConfig>, TlsError> {
    if let Some(config) = cached_client_config(ca_cert_path) {
        return Ok(config);
    }

    let path = ca_cert_path.to_owned();
    match time::timeout(
        CA_LOAD_TIMEOUT,
        task::spawn_blocking(move || refresh_client_config(&path)),
    )
    .await
    {
        Ok(Ok(result)) => result,
        Ok(Err(err)) => Err(format!("failed to load CA certificate {ca_cert_path}: {err}").into()),
        Err(_) => Err(format!(
            "timed out after {CA_LOAD_TIMEOUT:?} loading CA certificate {ca_cert_path}"
        )
        .into()),
    }
}

/// Validates the CA bundle and builds an isolated TLS 1.3 client config without mutating the global cache.
pub fn validate_ca_bundle(ca_cert_path: &str) -> Result<Arc<ClientConfig>, TlsError> {
    Ok(Arc::new(build_client_config(ca_cert_path)?))
}

/// Builds a TLS 1.3-only client connector without mutating the global cache.
///
/// Blocking on purpose: this is the config-validation entry point, which must
/// observe the CA file as it is on disk without polluting the active CA cache.
pub fn connector(ca_cert_path: &str) -> Result<TlsConnector, TlsError> {
    Ok(connector_from(validate_ca_bundle(ca_cert_path)?))
}

/// Wraps an already-loaded client config in a connector.
pub fn connector_from(config: Arc<ClientConfig>) -> TlsConnector {
    TlsConnector::from(config)
}

/// Reads the CA bundle, builds the client config, and atomically refreshes the cache entry for `ca_cert_path`.
pub fn refresh_client_config(ca_cert_path: &str) -> Result<Arc<ClientConfig>, TlsError> {
    let config = Arc::new(build_client_config(ca_cert_path)?);
    client_configs().insert(ca_cert_path.to_owned(), Arc::clone(&config));
    Ok(config)
}

/// Builds a TLS 1.3-only rustls client config with the UK ALPN and 0-RTT
/// disabled, trusting only the configured CA. Shared by the TLS/TCP and QUIC
/// client carriers.
fn build_client_config(ca_cert_path: &str) -> Result<ClientConfig, TlsError> {
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

fn cached_client_config(ca_cert_path: &str) -> Option<Arc<ClientConfig>> {
    client_configs().get(ca_cert_path).cloned()
}

/// Locks the config cache, recovering from a poisoned lock: the cached configs
/// are immutable once built, so a panicking holder cannot leave torn state.
fn client_configs() -> MutexGuard<'static, HashMap<String, Arc<ClientConfig>>> {
    CLIENT_CONFIGS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
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

    /// Self-signed `localhost` test certificate, used here only as CA trust
    /// material to exercise config loading.
    const CA_PEM: &str = r"-----BEGIN CERTIFICATE-----
MIIDSTCCAjGgAwIBAgIUEX51v2igsFngMQTuqhBx+gKL2MswDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDcwMzEzNTM0MVoXDTM2MDYz
MDEzNTM0MVowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAhf3zqFeac7mRJTkyoPMwXUtvgnKcY3ydON4Q3cMrxrd0
qn2leXJObMP846YgGBtKYu3cDo01qK+cN1rY4l/3iNqa4VOYJ3ckmUTEQhmCG78i
XIxR9+488rWsxrhJ4GtGj/jd7UaJM9RMs2bb+7KzSj8t6t+Q1MEKsPeqQZ1wBW9S
wgYLMmrP5eNYFgEgt8KI2r/p+Lf2rbGqu/OdzWkekDbuJq+wqUsEtEnE4x5ELJEE
axEv+savJVWGSvBUkU6sWU8s0iLNiQKMBjAd/vTbqD+NVGihNrE0S0o0S4oxtHhu
wwPbfk3bkGV2Z5QwTMI48AhrcoELMuQjO9wZygLHKQIDAQABo4GSMIGPMB0GA1Ud
DgQWBBT8yAuXKconl4iNVuGmhUJIuVZW5zAfBgNVHSMEGDAWgBT8yAuXKconl4iN
VuGmhUJIuVZW5zAaBgNVHREEEzARgglsb2NhbGhvc3SHBH8AAAEwDAYDVR0TAQH/
BAIwADAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDQYJKoZI
hvcNAQELBQADggEBAESMmK/ln9SXy8uevLxfdf0oKE4UC9CyyMj2FPOWSnpvwLJ4
KI5axpyV3uP4Afd/lH6W47OcvQ9Ah0hSEVY/Xi+sAfLdjPmp3YpTtHP605Bj0y+A
O2F21JkBh/ZVA2SbI9MCg13XBPfrmqarPxIVlye4kxbD4ZDN5Zp0DLjoIIWWGv2n
6MuVnlvftL6nyPvc8EyPLM6wxiisxlB/D7jx9tL+GuLHcvXDuxQIkjB7MMWWfERM
hpwf7QVVYCCnRNdlxk/xa6pr54CMysA75BlDBaVjyqK8Uy74DHL7APCN9opoV5ws
vX1BONgh2gSRGBFiii6imzEAwefkUtYAvAQy1xw=
-----END CERTIFICATE-----
";

    /// A second, unrelated test certificate, used to prove that a changed CA
    /// path or a CA rotated in place is not served a stale config.
    const OTHER_CA_PEM: &str = r"-----BEGIN CERTIFICATE-----
MIIDSTCCAjGgAwIBAgIUbKiGvhPFpGKNHR7j/6IXUhFdHiswDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDcxMzA5MTEzMloXDTM2MDcx
MDA5MTEzMlowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAkFhamPCkNJ11kWw3cFy+/8mokhXfr21B6uD5uCXYru+2
RxnV0ALFBzfA42ZcRuesSmlwauQKBnwYD6VfYNJWL0n+UibPI57cNW5yDQg04PY9
hMoexD9Ls9e2DSpP7Xa2ROx5kbI+1epR1Couu7vFcIVHahz7y8O/QH97xqrMBzmP
4EEEQKYi61YvUbHRYdFLOJZA2qe2T9CMJVQkwGI2vGHlUpNdP7BYFqj787Y/d+DI
2nnS/UFm7Hr1S3oBdwkcoqdPC4wqSq4akyYppKuWS9/fpyC+Oo2XCAFQ47YsPguV
2UjmoBG4hIycdi9ffAKUH9O3lzp7FYT5uIhwG4PwywIDAQABo4GSMIGPMB0GA1Ud
DgQWBBQgGGr6Btii4e151B3kGUK0enNy9DAfBgNVHSMEGDAWgBQgGGr6Btii4e15
1B3kGUK0enNy9DAaBgNVHREEEzARgglsb2NhbGhvc3SHBH8AAAEwDAYDVR0TAQH/
BAIwADAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDQYJKoZI
hvcNAQELBQADggEBABhyQN2prI40OBsUAMkNtwIGP1ApVuTMKHd7KyA/NB+WIW1Q
W5tBG2g375X5BX8H9+FlVV57Y5lLf0ypUI7Dp6Kwx3Opd77r1IUGT4/SltUxAa04
0epEQiIKXl/m7dV+XqKMzftn/q92ZXib3/Cy+3SdYoUoD/p4sXcvJ27Dt6pZFHru
Eyk0ziHhZXvMWYm8k5HUx4/KJrJ14v50Y3ySU7B9FnqwMztL4voIQpA7GeSfsQZY
a2QH+2MZeMVBaZQ8jAjq24WcpAM1Hx26UOmIy85/NvPFZBbT8ggH2r8CKYjiDqcL
C2n4SLoR1xpiEaImSSin581IyIJ4vFLJYsUfPJ8=
-----END CERTIFICATE-----
";

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

    #[tokio::test]
    async fn shares_one_client_config_per_ca_path() {
        let path = temp_file("shared-ca", CA_PEM.as_bytes());

        let first = shared_client_config(&path).await.unwrap();
        let second = shared_client_config(&path).await.unwrap();

        // The second call must be served from the cache, not re-read.
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(first.alpn_protocols, vec![ALPN_PROTOCOL.to_vec()]);
        assert!(!first.enable_early_data);

        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn does_not_serve_a_cached_config_for_another_ca_path() {
        let path = temp_file("first-ca", CA_PEM.as_bytes());
        let other_path = temp_file("second-ca", OTHER_CA_PEM.as_bytes());

        let first = shared_client_config(&path).await.unwrap();
        let other = shared_client_config(&other_path).await.unwrap();

        assert!(!Arc::ptr_eq(&first, &other));

        let _ = fs::remove_file(path);
        let _ = fs::remove_file(other_path);
    }

    #[tokio::test]
    async fn reload_validation_refreshes_a_ca_rotated_in_place() {
        let path = temp_file("rotated-ca", CA_PEM.as_bytes());

        let before = shared_client_config(&path).await.unwrap();
        fs::write(&path, OTHER_CA_PEM.as_bytes()).unwrap();
        let _refreshed = refresh_client_config(&path).unwrap();
        let after = shared_client_config(&path).await.unwrap();

        assert!(!Arc::ptr_eq(&before, &after));

        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn config_validation_does_not_pollute_active_ca_cache() {
        let path = temp_file("unpolluted-ca", CA_PEM.as_bytes());

        let before = shared_client_config(&path).await.unwrap();
        fs::write(&path, OTHER_CA_PEM.as_bytes()).unwrap();
        // Validation must read the new CA without mutating the shared cache.
        let _connector = connector(&path).unwrap();
        let active = shared_client_config(&path).await.unwrap();

        assert!(Arc::ptr_eq(&before, &active));

        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn shared_missing_ca_error_includes_path() {
        let path = temp_missing_file("shared-missing-ca");

        let error = shared_client_config(&path).await.unwrap_err().to_string();

        assert!(error.contains(&path));
        assert!(cached_client_config(&path).is_none());
    }

    #[tokio::test]
    async fn shared_invalid_ca_is_not_cached() {
        let path = temp_file("shared-invalid-ca", b"not a certificate");

        let error = shared_client_config(&path).await.unwrap_err().to_string();

        assert!(error.contains(&path));
        assert!(cached_client_config(&path).is_none());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn builds_a_tls13_only_config_with_the_uk_alpn() {
        let path = temp_file("build-ca", CA_PEM.as_bytes());

        let config = build_client_config(&path).unwrap();

        assert_eq!(config.alpn_protocols, vec![ALPN_PROTOCOL.to_vec()]);
        assert!(!config.enable_early_data);

        let _ = fs::remove_file(path);
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
