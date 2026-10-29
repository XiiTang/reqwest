#![cfg(all(not(target_arch = "wasm32"), feature = "socks", feature = "__rustls"))]
use hyper_util::client::legacy::connect::{
    OwnedTransport, SocketAdmission, SocketAdmissionRefused,
};
use std::{
    cell::Cell,
    future::Future,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
trait Io: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Io for T {}
type BoxIo = Box<dyn Io>;
#[derive(Clone, Default)]
struct Tasks(Arc<TaskState>);
#[derive(Default)]
struct TaskState {
    live: AtomicUsize,
    changed: tokio::sync::Notify,
}
struct TaskDone(Tasks);
impl Drop for TaskDone {
    fn drop(&mut self) {
        self.0 .0.live.fetch_sub(1, Ordering::SeqCst);
        self.0 .0.changed.notify_waiters();
    }
}
impl<F: Future + Send + 'static> hyper::rt::Executor<F> for Tasks
where
    F::Output: Send,
{
    fn execute(&self, future: F) {
        self.0.live.fetch_add(1, Ordering::SeqCst);
        let task = TaskDone(self.clone());
        tokio::spawn(async move {
            let _task = task;
            let _ = future.await;
        });
    }
}
impl Tasks {
    async fn idle(&self) {
        loop {
            let changed = self.0.changed.notified();
            if self.0.live.load(Ordering::SeqCst) == 1 {
                return;
            }
            changed.await;
        }
    }
}
#[derive(Default)]
struct Account {
    calls: AtomicUsize,
    live: AtomicUsize,
    changed: tokio::sync::Notify,
}
struct Permit(Arc<Account>, Cell<()>);
impl Drop for Permit {
    fn drop(&mut self) {
        self.0.live.fetch_sub(1, Ordering::SeqCst);
        self.0.changed.notify_waiters();
    }
}
impl Account {
    fn admission(self: &Arc<Self>) -> SocketAdmission {
        let account = self.clone();
        SocketAdmission::new(move |_| {
            account.calls.fetch_add(1, Ordering::SeqCst);
            account.live.fetch_add(1, Ordering::SeqCst);
            Ok::<_, std::io::Error>(Permit(account.clone(), Cell::new(())))
        })
    }
    async fn closed(&self) {
        loop {
            let changed = self.changed.notified();
            if self.live.load(Ordering::SeqCst) == 0 {
                return;
            }
            changed.await;
        }
    }
}
fn tls() -> tokio_rustls::TlsAcceptor {
    let rcgen::CertifiedKey { cert, signing_key } = rcgen::generate_simple_self_signed(vec![
        "localhost".into(),
        "127.0.0.1".into(),
        "channel.invalid".into(),
    ])
    .unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into(),
    )
    .unwrap();
    tokio_rustls::TlsAcceptor::from(Arc::new(config))
}
async fn head(io: &mut BoxIo) -> String {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        assert!(bytes.len() < 8192);
        bytes.push(io.read_u8().await.unwrap());
    }
    String::from_utf8(bytes).unwrap()
}
async fn socks(io: &mut BoxIo, v5: bool, accept: bool) {
    if v5 {
        assert_eq!(io.read_u8().await.unwrap(), 5);
        let n = io.read_u8().await.unwrap();
        let mut methods = vec![0; n as usize];
        io.read_exact(&mut methods).await.unwrap();
        io.write_all(&[5, 0]).await.unwrap();
        let mut prefix = [0; 4];
        io.read_exact(&mut prefix).await.unwrap();
        assert_eq!(&prefix[..3], &[5, 1, 0]);
        let n = match prefix[3] {
            1 => 4,
            4 => 16,
            3 => io.read_u8().await.unwrap() as usize,
            n => panic!("address type {n}"),
        };
        let mut address = vec![0; n + 2];
        io.read_exact(&mut address).await.unwrap();
        io.write_all(&[5, if accept { 0 } else { 1 }, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
    } else {
        let mut prefix = [0; 8];
        io.read_exact(&mut prefix).await.unwrap();
        assert_eq!(&prefix[..2], &[4, 1]);
        // The pinned SOCKS4 encoder writes an empty USERID byte and its terminator.
        assert_eq!(io.read_u8().await.unwrap(), 0);
        assert_eq!(io.read_u8().await.unwrap(), 0);
        io.write_all(&[0, if accept { 90 } else { 91 }, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
    }
}
#[derive(Clone, Copy, Debug)]
enum Route {
    Direct,
    HttpProxy,
    HttpsProxy,
    Socks4,
    Socks5,
}
#[derive(Clone, Copy, Debug)]
enum Backend {
    Rustls,
    #[cfg(feature = "__native-tls")]
    Native,
}
fn backend(builder: reqwest::ClientBuilder, which: Backend) -> reqwest::ClientBuilder {
    match which {
        Backend::Rustls => builder.tls_backend_rustls(),
        #[cfg(feature = "__native-tls")]
        Backend::Native => builder.tls_backend_native(),
    }
}
fn backends() -> Vec<Backend> {
    vec![
        Backend::Rustls,
        #[cfg(feature = "__native-tls")]
        Backend::Native,
    ]
}
async fn http(mut io: BoxIo, n: usize) {
    for _ in 0..n {
        assert!(head(&mut io).await.starts_with("GET "));
        io.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
            .await
            .unwrap();
    }
    match io.read(&mut [0]).await {
        Ok(0) => (),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
            ) => {}
        result => panic!("expected physical close after client drop: {result:?}"),
    }
}
#[tokio::test]
async fn direct_tls_connect_and_socks_keep_the_same_socket_permit_until_close() {
    tokio::time::timeout(std::time::Duration::from_secs(90), async {
        for backend_kind in backends() {
            for route in [
                Route::Direct,
                Route::HttpProxy,
                Route::HttpsProxy,
                Route::Socks4,
                Route::Socks5,
            ] {
                for secure in [false, true] {
                    let acceptor = tls();
                    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                    let address = listener.local_addr().unwrap();
                    let server = tokio::spawn(async move {
                        let (tcp, _) = listener.accept().await.unwrap();
                        let mut io: BoxIo = Box::new(tcp);
                        if matches!(route, Route::HttpsProxy) {
                            io = Box::new(acceptor.accept(io).await.unwrap());
                        }
                        match route {
                            Route::HttpProxy | Route::HttpsProxy if secure => {
                                assert!(head(&mut io).await.starts_with("CONNECT "));
                                io.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                                    .await
                                    .unwrap();
                            }
                            Route::Socks4 => socks(&mut io, false, true).await,
                            Route::Socks5 => socks(&mut io, true, true).await,
                            _ => (),
                        }
                        if secure {
                            io = Box::new(acceptor.accept(io).await.unwrap());
                        }
                        http(io, 2).await;
                    });
                    let account = Arc::new(Account::default());
                    let tasks = Tasks::default();
                    let mut builder = backend(reqwest::Client::builder(), backend_kind)
                        .no_proxy()
                        .http1_only()
                        .pool_idle_timeout(None)
                        .executor(tasks.clone())
                        .tls_info(true)
                        .tls_danger_accept_invalid_certs(true)
                        .socket_admission(Some(account.admission()));
                    let scheme = if secure { "https" } else { "http" };
                    let url = if matches!(route, Route::Direct) {
                        format!("{scheme}://{address}/")
                    } else {
                        format!("{scheme}://127.0.0.1/resource")
                    };
                    let proxy_scheme = match route {
                        Route::Direct => None,
                        Route::HttpProxy => Some("http"),
                        Route::HttpsProxy => Some("https"),
                        Route::Socks4 => Some("socks4"),
                        Route::Socks5 => Some("socks5"),
                    };
                    if let Some(scheme) = proxy_scheme {
                        builder = builder
                            .proxy(reqwest::Proxy::all(format!("{scheme}://{address}")).unwrap());
                    }
                    let client = builder.build().unwrap();
                    for _ in 0..2 {
                        let response = client.get(&url).send().await.unwrap_or_else(|e| {
                            panic!("{backend_kind:?} {route:?} tls={secure}: {e:?}")
                        });
                        assert_eq!(
                            account.live.load(Ordering::SeqCst),
                            1,
                            "after response headers: {route:?}"
                        );
                        if secure && matches!(route, Route::Direct) {
                            assert!(response
                                .extensions()
                                .get::<reqwest::tls::TlsInfo>()
                                .unwrap()
                                .peer_certificate()
                                .is_some());
                        }
                        drop(response);
                        tasks.idle().await;
                        assert_eq!(
                            account.live.load(Ordering::SeqCst),
                            1,
                            "request/proxy wrapper drop must retain the socket permit"
                        );
                    }
                    assert_eq!(
                        account.calls.load(Ordering::SeqCst),
                        1,
                        "reuse has no new socket admission"
                    );
                    drop(client);
                    server.await.unwrap();
                    account.closed().await;
                    assert_eq!(account.live.load(Ordering::SeqCst), 0);
                }
            }
        }
    })
    .await
    .unwrap();
}
#[derive(Debug)]
struct Refused;
impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("fixture account refused")
    }
}
impl std::error::Error for Refused {}
#[derive(Debug)]
struct Addresses;
impl reqwest::dns::Resolve for Addresses {
    fn resolve(&self, _: reqwest::dns::Name) -> reqwest::dns::Resolving {
        Box::pin(async {
            Ok(Box::new(
                vec![
                    "127.0.0.2:80".parse().unwrap(),
                    "127.0.0.1:80".parse().unwrap(),
                ]
                .into_iter(),
            ) as reqwest::dns::Addrs)
        })
    }
}
fn has<T: std::error::Error + 'static>(error: &reqwest::Error) -> bool {
    let mut next: Option<&(dyn std::error::Error + 'static)> = Some(error);
    while let Some(error) = next {
        if error.is::<T>() {
            return true;
        }
        next = error.source();
    }
    false
}
#[tokio::test]
async fn socket_refusal_keeps_its_cause_and_stops_socks_fallback_and_custom_retry() {
    for proxy in [None, Some("socks4"), Some("socks5")] {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let retries = Arc::new(AtomicUsize::new(0));
        let classified = retries.clone();
        let admission = SocketAdmission::new(move |_| {
            seen.fetch_add(1, Ordering::SeqCst);
            Err::<(), _>(Refused)
        });
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .dns_resolver(Arc::new(Addresses))
            .socket_admission(Some(admission))
            .retry(
                reqwest::retry::for_host("origin.invalid")
                    .no_budget()
                    .classify_fn(move |request| {
                        classified.fetch_add(1, Ordering::SeqCst);
                        request.retryable()
                    }),
            );
        if let Some(scheme) = proxy {
            builder =
                builder.proxy(reqwest::Proxy::all(format!("{scheme}://127.0.0.1:1")).unwrap());
        }
        let error = builder
            .build()
            .unwrap()
            .get("http://origin.invalid/")
            .send()
            .await
            .unwrap_err();
        assert!(
            has::<SocketAdmissionRefused>(&error),
            "{proxy:?}: {error:?}"
        );
        assert!(has::<Refused>(&error), "original cause must survive");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "no address or policy retry after refusal"
        );
        assert_eq!(retries.load(Ordering::SeqCst), 0);
    }
}
#[tokio::test]
async fn each_socks_address_attempt_has_its_own_socket_permit() {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        for v5 in [false, true] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (tcp, _) = listener.accept().await.unwrap();
                let mut first: BoxIo = Box::new(tcp);
                socks(&mut first, v5, false).await;
                assert_eq!(first.read(&mut [0]).await.unwrap(), 0);
                drop(first);
                let (tcp, _) = listener.accept().await.unwrap();
                let mut second: BoxIo = Box::new(tcp);
                socks(&mut second, v5, true).await;
                http(second, 1).await;
            });
            let account = Arc::new(Account::default());
            let admission_account = account.clone();
            let admission = SocketAdmission::new(move |_| {
                assert_eq!(
                    admission_account.live.load(Ordering::SeqCst),
                    0,
                    "previous physical dial must have returned its permit"
                );
                admission_account.calls.fetch_add(1, Ordering::SeqCst);
                admission_account.live.fetch_add(1, Ordering::SeqCst);
                Ok::<_, std::io::Error>(Permit(admission_account.clone(), Cell::new(())))
            });
            let client = reqwest::Client::builder()
                .no_proxy()
                .dns_resolver(Arc::new(Addresses))
                .pool_idle_timeout(None)
                .socket_admission(Some(admission))
                .proxy(
                    reqwest::Proxy::all(format!(
                        "{}://{address}",
                        if v5 { "socks5" } else { "socks4" }
                    ))
                    .unwrap(),
                )
                .build()
                .unwrap();
            let response = client.get("http://origin.invalid/").send().await.unwrap();
            drop(response);
            assert_eq!(account.calls.load(Ordering::SeqCst), 2);
            assert_eq!(account.live.load(Ordering::SeqCst), 1);
            drop(client);
            server.await.unwrap();
            account.closed().await;
        }
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn ssh_style_owned_dialer_keeps_channel_memory_and_uses_no_socket_admission() {
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        for backend_kind in backends() {
            for secure in [false, true] {
                let acceptor = tls();
                let memory = Arc::new(Account::default());
                let held = memory.clone();
                let tasks = Tasks::default();
                let (peers, mut peer) = tokio::sync::mpsc::unbounded_channel();
                let socket_calls = Arc::new(AtomicUsize::new(0));
                let called = socket_calls.clone();
                let client = backend(reqwest::Client::builder(), backend_kind)
                    .no_proxy()
                    .http1_only()
                    .pool_idle_timeout(None)
                    .executor(tasks.clone())
                    .tls_danger_accept_invalid_certs(true)
                    .socket_admission(Some(SocketAdmission::new(move |_| {
                        called.fetch_add(1, Ordering::SeqCst);
                        Err::<(), _>(Refused)
                    })))
                    .dialer(move |_| {
                        let (io, other) = tokio::io::duplex(4096);
                        peers.send(other).unwrap();
                        held.live.fetch_add(1, Ordering::SeqCst);
                        std::future::ready(Ok::<_, std::io::Error>(OwnedTransport::new(
                            io,
                            Permit(held.clone(), Cell::new(())),
                        )))
                    })
                    .build()
                    .unwrap();
                let server = tokio::spawn(async move {
                    let mut io: BoxIo = Box::new(peer.recv().await.unwrap());
                    if secure {
                        io = Box::new(acceptor.accept(io).await.unwrap());
                    }
                    http(io, 1).await;
                });
                let response = client
                    .get(format!(
                        "{}://channel.invalid/",
                        if secure { "https" } else { "http" }
                    ))
                    .send()
                    .await
                    .unwrap();
                drop(response);
                tasks.idle().await;
                assert_eq!(socket_calls.load(Ordering::SeqCst), 0);
                assert_eq!(memory.live.load(Ordering::SeqCst), 1);
                drop(client);
                server.await.unwrap();
                memory.closed().await;
            }
        }
    })
    .await
    .unwrap();
}
