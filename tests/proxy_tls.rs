//! Proxy TLS must not present the origin identity, including resumed sessions.
#![cfg(all(not(target_arch = "wasm32"), feature = "__rustls"))]
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Fixture {
    root: reqwest::Certificate,
    identity: reqwest::Identity,
    outer: tokio_rustls::TlsAcceptor,
    origin: tokio_rustls::TlsAcceptor,
}
fn fixture() -> Fixture {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Proxy isolation fixture CA");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let ca = CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    let roots = Arc::new(roots);
    let mut server = CertificateParams::new(vec!["127.0.0.1".into()]).unwrap();
    server.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_key = KeyPair::generate().unwrap();
    let server_cert = server.signed_by(&server_key, &ca).unwrap();
    let make_server = |optional| {
        let verifier = rustls::server::WebPkiClientVerifier::builder(roots.clone());
        let verifier = if optional {
            verifier.allow_unauthenticated().build()
        } else {
            verifier.build()
        }
        .unwrap();
        let config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![server_cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
            )
            .unwrap();
        tokio_rustls::TlsAcceptor::from(Arc::new(config))
    };
    let mut client = CertificateParams::new(Vec::<String>::new()).unwrap();
    client.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_key = KeyPair::generate().unwrap();
    let client_cert = client.signed_by(&client_key, &ca).unwrap();
    Fixture {
        root: reqwest::Certificate::from_der(ca.der()).unwrap(),
        identity: reqwest::Identity::from_pem(
            format!("{}{}", client_cert.pem(), client_key.serialize_pem()).as_bytes(),
        )
        .unwrap(),
        outer: make_server(true),
        origin: make_server(false),
    }
}
async fn head(io: &mut (impl tokio::io::AsyncRead + Unpin)) -> String {
    let mut result = Vec::new();
    while !result.ends_with(b"\r\n\r\n") {
        assert!(result.len() < 8192);
        result.push(io.read_u8().await.unwrap());
    }
    String::from_utf8(result).unwrap()
}

#[tokio::test]
async fn https_proxy_never_uses_origin_identity_in_tunnel_or_forward_and_resumes_safely() {
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        for tunnel in [true, false] {
            let fixture = fixture();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let observed = Arc::new(Mutex::new(Vec::new()));
            let observed_server = observed.clone();
            let server = tokio::spawn(async move {
                for _ in 0..3 {
                    let (tcp, _) = listener.accept().await.unwrap();
                    let mut outer = fixture.outer.accept(tcp).await.unwrap();
                    assert!(outer.get_ref().1.peer_certificates().is_none_or(|certs| certs.is_empty()), "proxy received origin client identity");
                    let outer_kind = outer.get_ref().1.handshake_kind();
                    let request = head(&mut outer).await;
                    assert!(request.to_ascii_lowercase().contains("proxy-authorization: basic dXNlcjpwYXNz".to_ascii_lowercase().as_str()));
                    if tunnel {
                        assert!(request.starts_with("CONNECT 127.0.0.1:443 "));
                        outer.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await.unwrap();
                        let mut inner = fixture.origin.accept(outer).await.unwrap();
                        assert!(!inner.get_ref().1.peer_certificates().unwrap().is_empty(), "origin mTLS missing");
                        observed_server.lock().unwrap().push((outer_kind, inner.get_ref().1.handshake_kind()));
                        let request = head(&mut inner).await;
                        assert!(request.starts_with("GET /resource "));
                        assert!(!request.to_ascii_lowercase().contains("proxy-authorization"));
                        inner.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await.unwrap();
                        inner.shutdown().await.unwrap();
                    } else {
                        assert!(request.starts_with("GET http://127.0.0.1/resource "));
                        observed_server.lock().unwrap().push((outer_kind, None));
                        outer.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await.unwrap();
                        outer.shutdown().await.unwrap();
                    }
                }
            });
            let client = reqwest::Client::builder().no_proxy().retry(reqwest::retry::never()).http1_only()
                .tls_certs_only([fixture.root]).identity(fixture.identity)
                .proxy(reqwest::Proxy::all(format!("https://{address}")).unwrap().basic_auth("user", "pass"))
                .build().unwrap();
            for _ in 0..3 {
                let response = client.get(if tunnel { "https://127.0.0.1/resource" } else { "http://127.0.0.1/resource" }).send().await.unwrap();
                assert_eq!(response.bytes().await.unwrap().as_ref(), b"ok");
            }
            server.await.unwrap();
            let observations = observed.lock().unwrap();
            assert_eq!(observations[0].0, Some(rustls::HandshakeKind::Full));
            assert!(observations[1..].iter().any(|(outer, _)| *outer == Some(rustls::HandshakeKind::Resumed)), "proxy did not exercise session resumption: {observations:?}");
            if tunnel { assert!(observations[1..].iter().any(|(_, inner)| *inner == Some(rustls::HandshakeKind::Resumed)), "origin did not exercise session resumption: {observations:?}"); }
        }
    }).await.unwrap();
}
