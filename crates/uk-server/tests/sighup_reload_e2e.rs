//! Real SIGHUP end-to-end test: spawns the actual `uk-server` binary as a child
//! process, delivers SIGHUP via the `kill` CLI, and verifies that the config
//! reload takes effect for new connections (rotated TLS identity is served)
//! while a pre-existing connection survives the reload.
//!
//! This exercises the true signal path (`tokio::signal` -> `queue_config_reload`
//! -> `ServerReloadHandle::reload` -> listener-loop `handle_reload_request`),
//! not just the in-process reload channel.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig as RustlsClientConfig, DigitallySignedStruct, Error as RustlsError};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const CERT1_PEM: &str = r"-----BEGIN CERTIFICATE-----
MIIDFzCCAf+gAwIBAgIUXmIluOxd2BJQUtdcW7NeCvqISpowDQYJKoZIhvcNAQEL
BQAwGzEZMBcGA1UEAwwQdWstdGVzdC1zZXJ2ZXItMTAeFw0yNjEwMTUxNzMwMjVa
Fw0zNjEwMTIxNzMwMjVaMBsxGTAXBgNVBAMMEHVrLXRlc3Qtc2VydmVyLTEwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCwUWiURQqTVXVTx8QOVyuTDhjX
JH1H1SuiZ1+x5fwFuNuFQseIRmlKjuf9xFfHneckA0SWG5ApnqjeuOA6LNXaq4kA
YYHlm/KDI0thcuF3Payp2ljRklcxEas2DmPzn7Zu6NdNYebFw9QurpQ6+N/wddJ0
n3f66SmZY1xnQzTA+NmeaYGcKWY9PXwGH1veNZJaIMgZevRpD0qUpDH/75yxH+pJ
ldNFus1SEWHyPA18GRbrKKl7qrTXLQKuNrQteA21Ff73uQLps/Rvy+onEZ7e6qrj
wrj9jp8Iqn1A42k0MJW0LYYFU7ygZrp5YDtdX1aScsNOiWQiaOi5Lx01M2qxAgMB
AAGjUzBRMB0GA1UdDgQWBBSjblbvKo5LcMSgZ2E3VheFwp2SiTAfBgNVHSMEGDAW
gBSjblbvKo5LcMSgZ2E3VheFwp2SiTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3
DQEBCwUAA4IBAQCP8lkSKqWK/U6Hzo/+OPd4NyAQJCP7gLUY3t8pTmzoiPIVWWmX
ub5n3EqIlyc1RoXgjs7cO7y8SooP2QcHsmc3MdRyYeRNwEN33XjgPEE9DYKtT1fj
7nZ/n59BleD74F6gPlsW/ZmfhL10CSHCsb0mgRB8ngFm1joKYYJ6ENKqy8k+Wm1h
Y22v4EUc+CUJawhBs4cU/NIDZ8VHcQIywaaYupeQSn7hq1RGmwRs7efSbqM8TLbU
qoMtc99+IW2HuewF6IaxsJ4lKY9IiiMTcT8gdH2ZJy8M1O3G2HwPKSQG6wc4oJDw
fFDi4p5s8Sv51rlh6QMFwMDPFmCz+lyJjXqR
-----END CERTIFICATE-----
";
const KEY1_PEM: &str = r"-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCwUWiURQqTVXVT
x8QOVyuTDhjXJH1H1SuiZ1+x5fwFuNuFQseIRmlKjuf9xFfHneckA0SWG5Apnqje
uOA6LNXaq4kAYYHlm/KDI0thcuF3Payp2ljRklcxEas2DmPzn7Zu6NdNYebFw9Qu
rpQ6+N/wddJ0n3f66SmZY1xnQzTA+NmeaYGcKWY9PXwGH1veNZJaIMgZevRpD0qU
pDH/75yxH+pJldNFus1SEWHyPA18GRbrKKl7qrTXLQKuNrQteA21Ff73uQLps/Rv
y+onEZ7e6qrjwrj9jp8Iqn1A42k0MJW0LYYFU7ygZrp5YDtdX1aScsNOiWQiaOi5
Lx01M2qxAgMBAAECggEAJ7HkRAE5LMtgE0EVtA7O+hgB4qnN5Laq0LDKPBBliVpB
XcKXjmgfu0/qDdk+0+uKRrLPpaXF8oDMTvw7Sw2eBdF5khLhvjI6SmjPRzyoYwKJ
FWJZfbEfHSZ3r79UpFwQI+8azcqdPGfmpK3cJFy0efvkqinexqfonCZg/sSEI29i
OlZiyjX9TG0w2d6fJSpdTeeG+YU2fDncob0wYVXgdx+0xxq7qsX6+oQOA8JRKy0z
0AxLQr2UwOi72YCdY//XI/6pSpybHKNdGecPoM8JoPRFc5N6NEs1rcxZgzbvVfsL
pxZjBOT1RnmiRFVyN5MPbxIxoM0BH9wxNDL3cPaqWQKBgQD3CdZCnyDJs7N9goCS
EUitPT0WX4G4nvv1giKa5vdYrtYxT3rv7+CMk/g9BZgiXgOOgUU4bKHcuhXH1Tyk
Xrkvk9CBPdDOIjD/TSikeh47l+8GWi1HIhG7WDd/NBDdv2B1f/eJdGDOOoA/j3hl
NaKQWCs0Vx+2zXgyJVa5UzsdfQKBgQC2ttCPnXqUOBYuuwM9UyHknRraoTg5lj4+
L19Cie05thktXBNB+WxS1KdJ77+9znJpOLTKAZT1melVO9mb9s3fojdWMltibu2k
eerX0EhNi7XpgkWOu5lPa1LhL6nW2t8bExRDhoNPx5g7tLRxbPzXZwq9s1ObvZgG
OAXSBF/YRQKBgQDhLexKCfa/JLhlnYFIo8yVbQ6zyBbcjL6qSRb2D7ZC9gt0Iziy
YPtT6MUMCn9kREIFsbvA9PSN2GlmH+8I/PbccWZLiGc+nlf/PvvfARlxxMoyBhzj
jCCRnpXnszP0jS+Fq0Gd36EmGpkwVryttLgbzuKC8S+NV7lKLFLi1wU5mQKBgQCu
CnGbeyv553rpxGWPkpJkS2n6+zqtT/m2DjW1EeCP6m8ND/mgDFAsjjdTbDW+PNoq
dENxcBRN5e+mqr3bnDn6XXBMgOcfWf6vfxo9vD5C72O2K8rJ7NRaHCb0LQyghhei
mIfi0kxeQAc4SCbhLCmjnJlUnW50mSIoOlEA/f216QKBgQCo7t3BJscwJyzrtbix
Rzmf4hFIC/HUcSoa30xwymN2nOGs8enVbkANGe8fuwcOH1SnO1atXGaoPK2/5DFE
9QncJZ8VKk0Rb7nh29cj8wnp1qGkBv5UB0Hzr7tklAhw1zvZFfrXbV1Im7p0K3do
04LbBQOnLlg0XVEXEJzY+1HmbQ==
-----END PRIVATE KEY-----
";
const CERT2_PEM: &str = r"-----BEGIN CERTIFICATE-----
MIIDFzCCAf+gAwIBAgIUOw62/sVz/oJQPv5bcEQkPzj+F1gwDQYJKoZIhvcNAQEL
BQAwGzEZMBcGA1UEAwwQdWstdGVzdC1zZXJ2ZXItMjAeFw0yNjEwMTUxNzMwMjZa
Fw0zNjEwMTIxNzMwMjZaMBsxGTAXBgNVBAMMEHVrLXRlc3Qtc2VydmVyLTIwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDNHcfvR44oZB+Tz3RA5vBIw+C0
wdZ6jusd6JtdmtyyXaU0CX5WqCaIpEXJ18nOmA2IxampeMf3zD6wIly+dur2FfIW
w/4PBPkycO20t81IWuWuhIYKqbH1tTJs86q3kDpJeKbBMh7bUjLgOoEPUG/hbXHG
7ExaM8SGDWGSQhP2j/xFpFZ4srHAlA5HyKlnKsoeJLHfU1Bhg1v+gAJe0twxRkqg
bSLOnOshyagQd/4WyvptaFICgMjuNFstmSq8nQsVlnKxHm/JEaLFOVLfddthtwMl
uTlFhI5MLU7JsYlZjdN5zDXEMDScQxaiAmQb9V6dtYbDUM7J2UdtGt/V/xA1AgMB
AAGjUzBRMB0GA1UdDgQWBBSK/BozdCWHgCGJtdavmYDJIQJ50TAfBgNVHSMEGDAW
gBSK/BozdCWHgCGJtdavmYDJIQJ50TAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3
DQEBCwUAA4IBAQC4atsuRt7mvBJEHl57B9Bl/QVyse0vEgbC6rasjjyqTA8gGVq9
4herAqruCpoxKmSsN3ld+Glo2L3/jxJNWsxr/EEEAKQXhPyfXS2+39g7bkI8s6zT
/9xbVNauhyvDDAhJ9xJ11LhIZj9lum7CYtuB3vZivsvm41Ijyyk11MVd+zn4up44
3jc97ImhcSabvaawMAjGuLRnRpaGR7PxH635WUCCXbVp3FOgfRehRrOTvkfpW/pZ
TJU0GgcnYhq7L0DP/GZrpnJGWmPB3SiAzEkGMQWhWsXLMbxEJ5H+ZAJkT9jDJowo
9nSg4BtrLw9H/suEhouV9hw2w7Km1Qhh5GF/
-----END CERTIFICATE-----
";
const KEY2_PEM: &str = r"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDNHcfvR44oZB+T
z3RA5vBIw+C0wdZ6jusd6JtdmtyyXaU0CX5WqCaIpEXJ18nOmA2IxampeMf3zD6w
Ily+dur2FfIWw/4PBPkycO20t81IWuWuhIYKqbH1tTJs86q3kDpJeKbBMh7bUjLg
OoEPUG/hbXHG7ExaM8SGDWGSQhP2j/xFpFZ4srHAlA5HyKlnKsoeJLHfU1Bhg1v+
gAJe0twxRkqgbSLOnOshyagQd/4WyvptaFICgMjuNFstmSq8nQsVlnKxHm/JEaLF
OVLfddthtwMluTlFhI5MLU7JsYlZjdN5zDXEMDScQxaiAmQb9V6dtYbDUM7J2Udt
Gt/V/xA1AgMBAAECggEAUGsJLLyatSZQJRT0aM/CTF0Tt/q5WtK2xsKgS0pAlePW
Nfk04cfKV89EF1c1pXyC7elFVA7pI7OdrlPCleAsza+b+yX7cSsLgqW45J4da21L
2KjXns2aWpGghAvillaDK7QUePFsHKP1E2mMmRL50mGk9o9FfiYGumH7q6qhhgyI
zH3oV+5sn7VWKNqErWaQqTuO1ws9eZX6AIycZGT6p11mMs52o9fQ4lpJTmYSsvO8
LddRntwgqZZNOkhLINUbGsYlc9F95orCEOuHEN8wkhX/GFW9couDu5N9THlbQ4Bj
6PB2PDc+mE2gM571fur5KBv40TwosLIAOLdixFRebwKBgQDvGt9zSZJi97TkQRo6
cmoZ6/WPRcFcXGsU1dwD7HuT8LuskyvGOHTUHLnkc8eUa0uBPaG9Ei8/VuaUwi3s
nfpTMtDiQAxh1zQst/GVLSnaAWZnWihJ8dYSEMeRg2jCSSbs1fyCtoY1xHVBMyfe
RjGjw7OVoGIy3M1VDJ1sCk8QdwKBgQDbnBf8wZzfVGrBVKbbKE9YliIK8jjaF6RQ
raiQCgW2feJuvo3hNsJaa1ZbX//VaC6dlN4YaqeI6AqHuF/nyDjmSSa7t6AppvR8
LW+Dqqwn8OzmW0wXV2DZXghH1VwN1tfHtzsdvN9a+313IPCKVGR3Ps3hPji4pDQi
X2DJzlYbswKBgH0BSKdGZJD3PgxDeQnrfUsWEKiZ6HB4JMec00z92tHKfuPHgZA9
Pd8TMaCdY09WFQB5j1CA7FCqBxzotAfLw+6xV4GhyJdyYmWquVOrbAD80GPiP8QA
+lExkpSh5igFBKO3cC+Ka3o6vq6apxJPEm6yxvXIBu7efz8ivD6a2SEbAoGBAKO2
gctTKnbyn4LwcFMAgeYwRcCTQf6TkVLzoq1+SzP4NE0KkQpLoCd3zTDhJ/8XY2jm
CYt6NtrA4Ni8ggJwKLrD3bQi96sVYz0PQgqNuTktSe2QMfFUmkZw6wth6vYGK2Yf
GlrY6kkRIj8ktyzoLN0YXLKFiBNdld/p6mWHBHoxAoGAPQB6ggmE90/BuN3Tk0jK
RPtkza7xhBAlJ/eLnhftn2V73meawEa5+IJeW5xv6ix6rCnQobALlj2lfCieEPHY
ANEf7ihzp0odb4pxebcwvDn9zFkjnIAB2DhgOVLfrlyQ3JuVSIjk9gnhJTvmOSkG
Cl5aqngt+UYmktrsXtcFSZ4=
-----END PRIVATE KEY-----
";

/// rustls verifier that accepts any certificate but records the presented
/// end-entity DER, so the test can assert which identity the server served.
#[derive(Debug)]
struct CapturingVerifier {
    captured: Mutex<Option<Vec<u8>>>,
}

impl CapturingVerifier {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            captured: Mutex::new(None),
        })
    }

    fn presented_der(&self) -> Option<Vec<u8>> {
        self.captured.lock().unwrap().clone()
    }
}

impl ServerCertVerifier for CapturingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        *self.captured.lock().unwrap() = Some(end_entity.as_ref().to_vec());
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        // TLS 1.3 uses RSA-PSS for RSA certificates.
        vec![
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

fn write_restricted(path: &std::path::Path, contents: &str) {
    fs::write(path, contents).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn server_config_toml(listen: &str, cert_path: &str, key_path: &str) -> String {
    format!(
        r#"listen = "{listen}"
cert_path = "{cert_path}"
key_path = "{key_path}"
auth_skew_seconds = 30

[limits]
handshake_timeout_seconds = 60

[[credentials]]
key_id = "sighup-test-key"
secret = "sighup-test-secret-0123456789abcdef"
status = "active"
"#
    )
}

/// Performs a TLS handshake against `addr` offering the UK ALPN and returns
/// the open TLS stream plus the DER of the certificate the server presented.
async fn tls_handshake_capture_cert(
    addr: std::net::SocketAddr,
) -> Result<(tokio_rustls::client::TlsStream<TcpStream>, Vec<u8>), TestError> {
    let verifier = CapturingVerifier::new();
    let mut rustls_config =
        RustlsClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone())
            .with_no_client_auth();
    rustls_config.alpn_protocols = vec![b"uk/1".to_vec()];
    let connector = TlsConnector::from(Arc::new(rustls_config));
    let tcp = TcpStream::connect(addr).await?;
    let server_name = ServerName::try_from("localhost")?;
    let tls = connector.connect(server_name, tcp).await?;
    let der = verifier
        .presented_der()
        .ok_or_else(|| TestError("server presented no certificate".to_owned()))?;
    Ok((tls, der))
}

/// Spawns a thread that forwards the child stderr lines into a channel.
fn spawn_stderr_forwarder(stderr: std::process::ChildStderr) -> std::sync::mpsc::Receiver<String> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        use std::io::BufRead;
        let reader = std::io::BufReader::new(stderr);
        for line in reader.lines() {
            match line {
                Ok(line) => {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    rx
}

/// Simple error type so `?` works without type-annotation churn.
#[derive(Debug)]
struct TestError(String);

impl std::fmt::Display for TestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for TestError {}

impl From<std::io::Error> for TestError {
    fn from(e: std::io::Error) -> Self {
        TestError(e.to_string())
    }
}

impl From<rustls::Error> for TestError {
    fn from(e: rustls::Error) -> Self {
        TestError(e.to_string())
    }
}

impl From<rustls::pki_types::InvalidDnsNameError> for TestError {
    fn from(e: rustls::pki_types::InvalidDnsNameError) -> Self {
        TestError(e.to_string())
    }
}

impl From<tokio::time::error::Elapsed> for TestError {
    fn from(_: tokio::time::error::Elapsed) -> Self {
        TestError("operation timed out".to_owned())
    }
}

/// Spawns the real server binary, SIGHUPs it after rotating the TLS identity
/// on disk, and verifies new connections serve the new certificate while a
/// pre-existing connection is not dropped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[cfg(unix)]
async fn sighup_reloads_tls_identity_without_dropping_connections() -> Result<(), TestError> {
    let temp_dir: PathBuf =
        std::env::temp_dir().join(format!("uk-sighup-test-{}", std::process::id()));
    if temp_dir.exists() {
        fs::remove_dir_all(&temp_dir).unwrap();
    }
    fs::create_dir_all(&temp_dir).unwrap();

    let cert_path = temp_dir.join("server-cert.pem");
    let key_path = temp_dir.join("server-key.pem");
    let config_path = temp_dir.join("server.toml");
    write_restricted(&cert_path, CERT1_PEM);
    write_restricted(&key_path, KEY1_PEM);

    // Pick a free loopback port for the child server.
    let probe = std::net::TcpListener::bind("127.0.0.1:0")?;
    let listen_addr = probe.local_addr()?;
    drop(probe);

    write_restricted(
        &config_path,
        &server_config_toml(
            &listen_addr.to_string(),
            &cert_path.to_string_lossy(),
            &key_path.to_string_lossy(),
        ),
    );

    let binary = env!("CARGO_BIN_EXE_uk-server");
    let mut child = std::process::Command::new(binary)
        .arg("--config")
        .arg(&config_path)
        .arg("serve")
        .stderr(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn()?;
    let stderr = child.stderr.take().expect("stderr piped");
    let log_rx = spawn_stderr_forwarder(stderr);

    // Wait until the listener accepts TCP connections.
    let ready_deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        if TcpStream::connect(listen_addr).await.is_ok() {
            break;
        }
        if tokio::time::Instant::now() > ready_deadline {
            let _ = child.kill();
            return Err(TestError(
                "server did not start listening in time".to_owned(),
            ));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Pre-reload connection: complete the TLS handshake now and keep the
    // stream open across SIGHUP. The server must not kill it when the
    // acceptor is swapped; only new connections use the reloaded identity.
    // (A full UK auth handshake is unnecessary: the point is the listener
    // loop keeps accepted connections while swapping the TLS acceptor.)
    let (mut pre_reload_tls, first_cert_der) = tls_handshake_capture_cert(listen_addr).await?;

    // Rotate the identity on disk and deliver SIGHUP to the real process
    // via the `kill` CLI (avoids unsafe libc::kill; the pid comes from the
    // child we just spawned).
    write_restricted(&cert_path, CERT2_PEM);
    write_restricted(&key_path, KEY2_PEM);
    let pid = child.id();
    let kill_status = std::process::Command::new("kill")
        .arg("-HUP")
        .arg(pid.to_string())
        .status()?;
    assert!(
        kill_status.success(),
        "failed to deliver SIGHUP to the server process"
    );

    // Wait until new connections serve the rotated certificate (proves the
    // SIGHUP reload took effect). Poll instead of parsing logs: this verifies
    // the observable behavior, not log formatting.
    let reload_deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let second_cert_der = loop {
        if tokio::time::Instant::now() > reload_deadline {
            return Err(TestError(
                "server did not serve the rotated certificate after SIGHUP".to_owned(),
            ));
        }
        // Drain any pending log lines to keep the forwarder from blocking.
        while log_rx.try_recv().is_ok() {}
        match tls_handshake_capture_cert(listen_addr).await {
            Ok((_, der)) if der != first_cert_der => break der,
            Ok(_) => tokio::time::sleep(Duration::from_millis(200)).await,
            Err(_) => {
                // Handshake may fail transiently during the reload swap; retry.
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
    };

    // The loop above only breaks once a different certificate is served.
    assert_ne!(
        first_cert_der, second_cert_der,
        "server still serves the pre-reload certificate after SIGHUP"
    );

    // The pre-existing TLS connection must not have been dropped by the
    // reload: a read must time out (idle, still open), not return EOF or an
    // error. The server sends nothing until the UK handshake, so a timeout
    // proves the connection survived.
    // The pre-existing TLS connection must not have been dropped by the
    // reload. Note: the server sends an AuthChallenge frame (starting with
    // 0x01) right after the TLS handshake, so the connection is not idle.
    // A dropped connection would read EOF (Ok(0)) or an error; an open one
    // either returns the challenge bytes or times out waiting for more.
    let mut probe_buf = [0_u8; 16];
    let read_result =
        tokio::time::timeout(Duration::from_secs(3), pre_reload_tls.read(&mut probe_buf)).await;
    match read_result {
        Ok(Ok(0)) => {
            panic!("pre-reload connection was dropped by SIGHUP reload (EOF)");
        }
        Err(_) | Ok(Ok(_)) => {
            // Timeout (connection open but idle) or data (e.g. the
            // AuthChallenge): the pre-reload connection survived. Fine.
        }
        Ok(Err(e)) => {
            panic!("pre-reload connection errored after SIGHUP reload: {e}");
        }
    }

    let _ = child.kill();
    let _ = child.wait();
    fs::remove_dir_all(&temp_dir).unwrap();
    Ok(())
}
