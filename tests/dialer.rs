//! A caller's dialer supplies each connection's byte stream in place of TCP.
#![cfg(all(not(target_arch = "wasm32"), feature = "__rustls"))]
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn head(io: &mut (impl tokio::io::AsyncRead + Unpin)) -> String {
    let mut result = Vec::new();
    while !result.ends_with(b"\r\n\r\n") {
        assert!(result.len() < 8192);
        result.push(io.read_u8().await.unwrap());
    }
    String::from_utf8(result).unwrap()
}

/// The dialer receives the request URI and connects to a listener whose
/// address the URI never names: no DNS lookup and no proxy is consulted.
#[tokio::test]
async fn http_runs_over_the_dialed_stream_and_ignores_proxies() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        for _ in 0..2 {
            let request = head(&mut stream).await;
            assert!(request.starts_with("GET /resource "), "{request}");
            assert!(request.contains("host: service.invalid:8080"), "{request}");
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
        }
    });
    let dialed = Arc::new(Mutex::new(Vec::new()));
    let seen = dialed.clone();
    let client = reqwest::Client::builder()
        .no_proxy()
        .proxy(reqwest::Proxy::all("http://dont.use.me.invalid").unwrap())
        .dialer(move |uri: http::Uri| {
            seen.lock().unwrap().push(uri.to_string());
            tokio::net::TcpStream::connect(address)
        })
        .build()
        .unwrap();
    for _ in 0..2 {
        let response = client
            .get("http://service.invalid:8080/resource")
            .send()
            .await
            .unwrap();
        assert_eq!(response.bytes().await.unwrap().as_ref(), b"ok");
    }
    server.await.unwrap();
    // The second request reused the pooled dialed connection.
    assert_eq!(*dialed.lock().unwrap(), ["http://service.invalid:8080/"]);
}

/// HTTPS runs TLS over the dialed stream with the client's own trust and
/// identity, verifying the origin's name, not the dialed peer's.
#[tokio::test]
async fn https_runs_tls_with_the_client_identity_over_the_dialed_stream() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let ca = CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    let mut server = CertificateParams::new(vec!["origin.invalid".into()]).unwrap();
    server.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_key = KeyPair::generate().unwrap();
    let server_cert = server.signed_by(&server_key, &ca).unwrap();
    let config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(
            rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .unwrap(),
        )
        .with_single_cert(
            vec![server_cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let mut client_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_key = KeyPair::generate().unwrap();
    let client_cert = client_params.signed_by(&client_key, &ca).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(tcp).await.unwrap();
        assert!(!tls.get_ref().1.peer_certificates().unwrap().is_empty());
        let request = head(&mut tls).await;
        assert!(request.starts_with("GET /secure "), "{request}");
        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
        tls.shutdown().await.unwrap();
    });
    let client = reqwest::Client::builder()
        .no_proxy()
        .http1_only()
        .tls_certs_only([reqwest::Certificate::from_der(ca.der()).unwrap()])
        .identity(
            reqwest::Identity::from_pem(
                format!("{}{}", client_cert.pem(), client_key.serialize_pem()).as_bytes(),
            )
            .unwrap(),
        )
        .dialer(move |_| tokio::net::TcpStream::connect(address))
        .build()
        .unwrap();
    let response = client
        .get("https://origin.invalid/secure")
        .send()
        .await
        .unwrap();
    assert_eq!(response.bytes().await.unwrap().as_ref(), b"ok");
    server.await.unwrap();
}

/// A dial failure is the request's connection error.
#[tokio::test]
async fn a_failed_dial_fails_the_request_as_a_connection_error() {
    let client = reqwest::Client::builder()
        .no_proxy()
        .dialer(|_| async {
            Err::<tokio::net::TcpStream, _>(std::io::Error::other("tunnel refused"))
        })
        .build()
        .unwrap();
    let error = client
        .get("http://service.invalid/")
        .send()
        .await
        .unwrap_err();
    assert!(error.is_connect(), "{error:?}");
}
