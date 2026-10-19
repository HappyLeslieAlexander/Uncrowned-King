//! Micro-benchmarks for the authentication hot paths.
//!
//! `compute_auth_tag` runs once per client handshake; `verify_auth_response_stateless`
//! runs once per server handshake and is the per-connection CPU cost of
//! authentication. Run with `cargo bench -p uk-auth`.

// criterion_group! expands to an undocumented public function.
#![allow(missing_docs)]

use std::hint::black_box;
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use uk_auth::{
    AuthChallenge, AuthResponse, Credential, compute_auth_tag, verify_auth_response_stateless,
};

fn fixture() -> (Vec<Credential>, [u8; 32], AuthChallenge, AuthResponse) {
    let credential = Credential::active(
        b"client-a".to_vec(),
        b"0123456789abcdef0123456789abcdef".to_vec(),
    )
    .unwrap();
    let exporter = [0x11; 32];
    let challenge = AuthChallenge {
        server_nonce: [0x22; 32],
        server_time: 1_700_000_000,
        server_capabilities: vec![1, 2, 3],
        limits: vec![4, 5, 6],
    };
    let client_nonce = [0x44; 32];
    let client_time = 1_700_000_001;
    let tag = compute_auth_tag(
        &credential.secret,
        &exporter,
        &challenge,
        &credential.key_id,
        &client_nonce,
        client_time,
        b"cap",
    )
    .unwrap();
    let response = AuthResponse {
        key_id: credential.key_id.clone(),
        client_nonce,
        client_time,
        client_capabilities: b"cap".to_vec(),
        tag,
    };
    (vec![credential], exporter, challenge, response)
}

fn bench_compute_tag(c: &mut Criterion) {
    let (credentials, exporter, challenge, response) = fixture();
    let credential = &credentials[0];
    let mut group = c.benchmark_group("auth");
    group.bench_function("compute_tag", |b| {
        b.iter(|| {
            black_box(
                compute_auth_tag(
                    black_box(&credential.secret),
                    black_box(&exporter),
                    black_box(&challenge),
                    black_box(&credential.key_id),
                    black_box(&response.client_nonce),
                    black_box(response.client_time),
                    black_box(&response.client_capabilities),
                )
                .unwrap(),
            )
        });
    });
    group.finish();
}

fn bench_verify_stateless(c: &mut Criterion) {
    let (credentials, exporter, challenge, response) = fixture();
    let now = 1_700_000_002;
    let skew = Duration::from_secs(300);
    let mut group = c.benchmark_group("auth");
    group.bench_function("verify_stateless", |b| {
        b.iter(|| {
            black_box(
                verify_auth_response_stateless(
                    black_box(&credentials),
                    black_box(&exporter),
                    black_box(&challenge),
                    black_box(&response),
                    black_box(now),
                    black_box(skew),
                )
                .unwrap(),
            )
        });
    });
    group.finish();
}

fn bench_roundtrip(c: &mut Criterion) {
    let (credentials, exporter, challenge, _) = fixture();
    let credential = &credentials[0];
    let now = 1_700_000_002;
    let skew = Duration::from_secs(300);
    let mut group = c.benchmark_group("auth");
    group.bench_function("roundtrip_compute_verify", |b| {
        b.iter(|| {
            let client_nonce = [0x44; 32];
            let tag = compute_auth_tag(
                &credential.secret,
                &exporter,
                &challenge,
                &credential.key_id,
                &client_nonce,
                now,
                b"cap",
            )
            .unwrap();
            let response = AuthResponse {
                key_id: credential.key_id.clone(),
                client_nonce,
                client_time: now,
                client_capabilities: b"cap".to_vec(),
                tag,
            };
            black_box(
                verify_auth_response_stateless(
                    &credentials,
                    &exporter,
                    &challenge,
                    &response,
                    now,
                    skew,
                )
                .unwrap(),
            )
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_compute_tag,
    bench_verify_stateless,
    bench_roundtrip
);
criterion_main!(benches);
