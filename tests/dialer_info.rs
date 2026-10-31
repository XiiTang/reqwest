#![cfg(all(not(target_arch = "wasm32"), feature = "__rustls"))]
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[derive(Clone, Debug, PartialEq)]
struct Facts(&'static str);
fn facts(info: &hyper_util::client::legacy::connect::Connected) {
    let mut extras = http::Extensions::new();
    info.get_extras(&mut extras);
    assert_eq!(extras.get::<Facts>(), Some(&Facts("caller peer")));
}
async fn head(io: &mut (impl tokio::io::AsyncRead + Unpin)) -> String {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        bytes.push(io.read_u8().await.unwrap());
        assert!(bytes.len() < 8192);
    }
    String::from_utf8(bytes).unwrap()
}
#[tokio::test]
async fn metadata_forwarding_pool_admission_and_both_guards_survive_request_conversion() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let mut received = 0;
        while received < 2 {
            let (mut stream, _) = listener.accept().await.unwrap();
            loop {
                let mut bytes = Vec::new();
                while !bytes.ends_with(b"\r\n\r\n") {
                    match stream.read_u8().await {
                        Ok(byte) => bytes.push(byte),
                        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => break,
                        Err(error) => panic!("{error}"),
                    }
                }
                if bytes.is_empty() {
                    break;
                }
                assert!(String::from_utf8(bytes)
                    .unwrap()
                    .starts_with("GET http://origin.invalid/ok HTTP/1.1"));
                received += 1;
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .await
                    .unwrap();
                if received == 2 {
                    return;
                }
            }
        }
    });
    let dials = Arc::new(AtomicUsize::new(0));
    let count = dials.clone();
    let client = reqwest::Client::builder()
        .no_proxy()
        .dialer_with_info(move |_, budget| {
            let count = count.clone();
            async move {
                count.fetch_add(1, Ordering::SeqCst);
                Ok((
                    tokio::net::TcpStream::connect(address).await?,
                    true,
                    Facts("caller peer"),
                    budget,
                ))
            }
        })
        .build()
        .unwrap();
    for order in [false, true] {
        let reservations = Arc::new(AtomicUsize::new(0));
        let reserved = reservations.clone();
        let oauth = move || {
            reserved.fetch_add(1, Ordering::SeqCst);
            Ok::<_, std::io::Error>(())
        };
        let policy = |info: &hyper_util::client::legacy::connect::Connected| {
            facts(info);
            Err::<(), _>(std::io::Error::other("policy refusal"))
        };
        let request = client
            .get("http://origin.invalid/refuse")
            .connection_admission(|info| async move {
                facts(&info);
                Ok::<_, std::io::Error>(())
            });
        let request = if order {
            request.connection_guard(policy).dispatch_guard(oauth)
        } else {
            request.dispatch_guard(oauth).connection_guard(policy)
        };
        let error = request.send().await.unwrap_err();
        assert!(format!("{error:?}").contains("policy refusal"));
        assert_eq!(reservations.load(Ordering::SeqCst), 0);
        let response = client
            .get("http://origin.invalid/ok")
            .connection_admission(|info| async move {
                facts(&info);
                Ok::<_, std::io::Error>(())
            })
            .connection_guard(|info| {
                facts(info);
                Ok::<_, std::io::Error>(())
            })
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.extensions().get::<Facts>(),
            Some(&Facts("caller peer"))
        );
        response.bytes().await.unwrap();
    }
    assert!(dials.load(Ordering::SeqCst) >= 1);
    peer.await.unwrap();
}
#[tokio::test(start_paused = true)]
async fn callback_acquisition_is_outside_connect_timeout_in_both_service_constructions() {
    for layered in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            head(&mut stream).await;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .connect_timeout(Duration::from_millis(100))
            .dialer_with_info(move |_, budget| async move {
                assert_eq!(budget, Some(Duration::from_millis(100)));
                tokio::time::sleep(Duration::from_secs(60)).await;
                Ok((
                    tokio::net::TcpStream::connect(address).await?,
                    false,
                    Facts("caller peer"),
                    Some(Duration::from_millis(50)),
                ))
            });
        if layered {
            builder = builder.connector_layer(tower::layer::util::Identity::new());
        }
        builder
            .build()
            .unwrap()
            .get("http://origin.invalid/")
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        peer.await.unwrap();
    }
}
#[tokio::test(start_paused = true)]
async fn origin_tls_uses_only_returned_budget_including_zero() {
    for left in [Duration::ZERO, Duration::from_millis(20)] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
        });
        let client = reqwest::Client::builder()
            .no_proxy()
            .connect_timeout(Duration::from_millis(100))
            .dialer_with_info(move |_, _| async move {
                tokio::time::sleep(Duration::from_secs(60)).await;
                Ok((
                    tokio::net::TcpStream::connect(address).await?,
                    false,
                    Facts("caller peer"),
                    Some(left),
                ))
            })
            .build()
            .unwrap();
        let start = tokio::time::Instant::now();
        let error = client
            .get("https://origin.invalid/")
            .send()
            .await
            .unwrap_err();
        assert!(error.is_connect() && error.is_timeout(), "{error:?}");
        assert!(start.elapsed() < Duration::from_secs(60) + Duration::from_millis(100));
        peer.abort();
        let _ = peer.await;
    }
}
#[tokio::test]
async fn invalid_budget_is_refused_without_sending_a_request() {
    let client = reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(Duration::from_millis(10))
        .dialer_with_info(|_, _| async {
            let (stream, _) = tokio::io::duplex(1024);
            Ok((stream, false, (), Some(Duration::from_millis(11))))
        })
        .build()
        .unwrap();
    let error = client
        .get("http://origin.invalid/")
        .send()
        .await
        .unwrap_err();
    assert!(format!("{error:?}").contains("invalid connect budget"));
}

#[cfg(feature = "http2")]
#[tokio::test]
async fn origin_tls_preserves_caller_metadata_and_actual_alpn() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    for native in [false, true] {
        #[cfg(not(feature = "__native-tls"))]
        if native {
            continue;
        }
        let certified = rcgen::generate_simple_self_signed(vec!["origin.invalid".into()]).unwrap();
        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![certified.cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(
                    certified.signing_key.serialize_der().into(),
                ),
            )
            .unwrap();
        config.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let stream = acceptor.accept(stream).await.unwrap();
            hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection(
                    hyper_util::rt::TokioIo::new(stream),
                    hyper::service::service_fn(|_: hyper::Request<hyper::body::Incoming>| async {
                        Ok::<_, std::convert::Infallible>(hyper::Response::new(
                            http_body_util::Full::new(bytes::Bytes::new()),
                        ))
                    }),
                )
                .await
                .unwrap();
        });
        let builder = reqwest::Client::builder()
            .no_proxy()
            .tls_backend_rustls()
            .tls_certs_only([reqwest::Certificate::from_der(certified.cert.der()).unwrap()]);
        #[cfg(feature = "__native-tls")]
        let builder = if native {
            builder.tls_backend_native()
        } else {
            builder
        };
        let client = builder
            .dialer_with_info(move |_, budget| async move {
                Ok((
                    tokio::net::TcpStream::connect(address).await?,
                    false,
                    Facts("caller peer"),
                    budget,
                ))
            })
            .build()
            .unwrap();
        let response = client
            .get("https://origin.invalid/")
            .connection_admission(|info| async move {
                facts(&info);
                assert!(info.is_negotiated_h2());
                Ok::<_, std::io::Error>(())
            })
            .connection_guard(|info| {
                facts(info);
                assert!(info.is_negotiated_h2());
                Ok::<_, std::io::Error>(())
            })
            .send()
            .await
            .unwrap();
        assert_eq!(response.version(), http::Version::HTTP_2);
        assert_eq!(
            response.extensions().get::<Facts>(),
            Some(&Facts("caller peer"))
        );
        response.bytes().await.unwrap();
        drop(client);
        peer.abort();
        let _ = peer.await;
    }
}
