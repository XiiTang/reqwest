//! The default rustls trust loads the platform's roots at the first TLS
//! certificate check, not with the client: a host with no CA roots can still
//! make plaintext requests, and a TLS connection there fails its handshake
//! with `PlatformTrustUnavailable` before any application byte is sent.
//! Supplied roots are still validated when the client is built.
//! The host-dependent parts run on Linux, where the platform verifier reads
//! roots from files; elsewhere the build-time controls run.
#![cfg(all(not(target_arch = "wasm32"), feature = "__rustls"))]
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn authority(name: &str) -> CertifiedIssuer<'static, KeyPair> {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap()
}

/// A TLS server for 127.0.0.1 signed by `ca`, answering one request per
/// connection, and how many application bytes each connection read.
async fn tls_server(
    ca: &CertifiedIssuer<'static, KeyPair>,
) -> (
    std::net::SocketAddr,
    tokio::sync::mpsc::UnboundedReceiver<Result<usize, std::io::Error>>,
) {
    let mut server = CertificateParams::new(vec!["127.0.0.1".into()]).unwrap();
    server.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let key = KeyPair::generate().unwrap();
    let cert = server.signed_by(&key, ca).unwrap();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (report, reports) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            let report = report.clone();
            tokio::spawn(async move {
                let result = async {
                    let mut tls = acceptor.accept(tcp).await?;
                    let mut head = Vec::new();
                    while !head.ends_with(b"\r\n\r\n") {
                        head.push(tls.read_u8().await?);
                    }
                    tls.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await?;
                    tls.shutdown().await?;
                    Ok(head.len())
                }
                .await;
                let _ = report.send(result);
            });
        }
    });
    (address, reports)
}

/// Whether `error`'s chain holds the given rustls failure, looking inside the
/// I/O errors tokio-rustls reports it with.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn rustls_failure(
    error: &(dyn std::error::Error + 'static),
    matches: &dyn Fn(&rustls::Error) -> bool,
) -> bool {
    if let Some(tls) = error.downcast_ref::<rustls::Error>() {
        if matches(tls) {
            return true;
        }
    }
    if let Some(inner) = error
        .downcast_ref::<std::io::Error>()
        .and_then(std::io::Error::get_ref)
    {
        if rustls_failure(inner, matches) {
            return true;
        }
    }
    error
        .source()
        .is_some_and(|source| rustls_failure(source, matches))
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn trust_unavailable(error: &rustls::Error) -> bool {
    matches!(error, rustls::Error::Other(other)
        if other.0.downcast_ref::<reqwest::tls::PlatformTrustUnavailable>().is_some())
}

#[tokio::test]
async fn platform_trust_loads_at_the_first_tls_connection() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    // rustls-native-certs reads only these when either is set: an empty file
    // and an empty directory are a host with no usable trust store.
    let empty = std::env::temp_dir().join(format!("reqwest-lazy-trust-{}", std::process::id()));
    std::fs::create_dir_all(&empty).unwrap();
    std::env::set_var(
        "SSL_CERT_FILE",
        if cfg!(target_os = "linux") {
            "/dev/null"
        } else {
            ""
        },
    );
    std::env::set_var("SSL_CERT_DIR", &empty);
    let ca = authority("Lazy trust fixture CA");
    let (address, mut reports) = tls_server(&ca).await;

    // The client builds, and plaintext needs no trust.
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let plain = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let plain_address = plain.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut tcp, _) = plain.accept().await.unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(tcp.read_u8().await.unwrap());
        }
        tcp.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
    });
    let answer = client
        .get(format!("http://{plain_address}/"))
        .send()
        .await
        .unwrap();
    assert_eq!(answer.status(), 200);

    // TLS fails its handshake with the typed cause; the server reads no request.
    #[cfg(target_os = "linux")]
    {
        let error = client
            .get(format!("https://{address}/"))
            .send()
            .await
            .unwrap_err();
        assert!(rustls_failure(&error, &trust_unavailable), "{error:?}");
        assert!(reports.recv().await.unwrap().is_err());
    }

    // Supplied roots are validated when the client is built.
    assert!(reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_der(b"not a certificate").unwrap())
        .build()
        .is_err());

    // Merged roots verify the server with no platform roots at all.
    let merged = reqwest::Client::builder()
        .no_proxy()
        .tls_certs_merge([reqwest::Certificate::from_der(ca.der()).unwrap()])
        .build()
        .unwrap();
    let answer = merged
        .get(format!("https://{address}/"))
        .send()
        .await
        .unwrap();
    assert_eq!(answer.status(), 200);
    assert!(reports.recv().await.unwrap().unwrap() > 0);

    // With platform roots present, an untrusted server is a certificate
    // failure, not unavailable trust.
    #[cfg(target_os = "linux")]
    {
        let other = authority("Unrelated fixture CA");
        let roots = empty.join("roots.pem");
        std::fs::write(&roots, other.pem()).unwrap();
        std::env::set_var("SSL_CERT_FILE", &roots);
        let platform = reqwest::Client::builder().no_proxy().build().unwrap();
        let error = platform
            .get(format!("https://{address}/"))
            .send()
            .await
            .unwrap_err();
        assert!(
            rustls_failure(&error, &|error| matches!(
                error,
                rustls::Error::InvalidCertificate(_)
            )),
            "{error:?}"
        );
        assert!(!rustls_failure(&error, &trust_unavailable), "{error:?}");
    }
    std::fs::remove_dir_all(&empty).unwrap();
}
