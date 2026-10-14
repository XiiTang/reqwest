//! Verify address attempts on the wire, before any HTTP bytes enter a tunnel.
#![cfg(all(
    not(target_arch = "wasm32"),
    feature = "socks",
    not(feature = "rustls-no-provider")
))]
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

#[tokio::test]
async fn local_dns_tries_fresh_tunnels_and_remote_dns_keeps_its_hostname() {
    for (remote, stall, ipv6) in [
        (false, false, false),
        (false, true, false),
        (false, false, true),
        (true, false, false),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        let first: SocketAddr = if ipv6 { "[::1]:80" } else { "127.0.0.2:80" }
            .parse()
            .unwrap();
        let server = async {
            let mut failed: Option<tokio::net::TcpStream> = None;
            for attempt in 0..if remote { 1 } else { 2 } {
                let (mut io, _) = listener.accept().await.unwrap();
                if let Some(mut previous) = failed.take() {
                    assert_eq!(previous.read(&mut [0; 1]).await.unwrap(), 0);
                }
                let mut greeting = [0; 3];
                io.read_exact(&mut greeting).await.unwrap();
                assert_eq!(greeting, [5, 1, 0]);
                io.write_all(&[5, 0]).await.unwrap();
                let mut prefix = [0; 4];
                io.read_exact(&mut prefix).await.unwrap();
                assert_eq!(&prefix[..3], &[5, 1, 0]);
                if remote {
                    assert_eq!(prefix[3], 3);
                    let n = io.read_u8().await.unwrap() as usize;
                    let mut host = vec![0; n];
                    io.read_exact(&mut host).await.unwrap();
                    assert_eq!(host, b"ordered.invalid");
                } else {
                    let expected = if attempt == 0 {
                        first.ip()
                    } else {
                        "127.0.0.1".parse().unwrap()
                    };
                    let bytes = match expected {
                        std::net::IpAddr::V4(ip) => {
                            assert_eq!(prefix[3], 1);
                            ip.octets().to_vec()
                        }
                        std::net::IpAddr::V6(ip) => {
                            assert_eq!(prefix[3], 4);
                            ip.octets().to_vec()
                        }
                    };
                    let mut address = vec![0; bytes.len()];
                    io.read_exact(&mut address).await.unwrap();
                    assert_eq!(address, bytes);
                }
                assert_eq!(io.read_u16().await.unwrap(), 80);
                if !remote && attempt == 0 {
                    if !stall {
                        io.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
                    }
                    failed = Some(io);
                } else {
                    io.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 80])
                        .await
                        .unwrap();
                    let mut head = Vec::new();
                    while !head.ends_with(b"\r\n\r\n") {
                        assert!(head.len() < 8192);
                        head.push(io.read_u8().await.unwrap());
                    }
                    assert!(head.starts_with(b"GET / HTTP/1.1\r\n"));
                    io.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await
                    .unwrap();
                }
            }
        };
        let client = reqwest::Client::builder()
            .proxy(
                reqwest::Proxy::all(format!(
                    "{}://{proxy}",
                    if remote { "socks5h" } else { "socks5" }
                ))
                .unwrap(),
            )
            .resolve_to_addrs("ordered.invalid", &[first, "127.0.0.1:80".parse().unwrap()])
            .connect_timeout(Duration::from_millis(800))
            .build()
            .unwrap();
        let sending = async {
            assert_eq!(
                client
                    .get("http://ordered.invalid/")
                    .send()
                    .await
                    .unwrap()
                    .bytes()
                    .await
                    .unwrap()
                    .as_ref(),
                b"ok"
            );
        };
        tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(sending, server);
        })
        .await
        .unwrap();
    }
}

/// Runs `test` on a paused clock, so only a timer can advance it; the
/// thread's end, read in real time, bounds a hang.
fn on_paused_clock<F: std::future::Future<Output = ()>>(test: impl FnOnce() -> F + Send + 'static) {
    let thread = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .unwrap()
            .block_on(test())
    });
    let hang = std::time::Instant::now() + Duration::from_secs(60);
    while !thread.is_finished() {
        assert!(std::time::Instant::now() < hang, "the request did not end");
        std::thread::sleep(Duration::from_millis(10));
    }
    thread.join().unwrap();
}

/// Reads one SOCKS5 greeting and the CONNECT that follows, answering the
/// greeting, and returns the CONNECT's IPv4 address.
async fn connect_request(io: &mut tokio::net::TcpStream) -> [u8; 4] {
    let mut greeting = [0; 3];
    io.read_exact(&mut greeting).await.unwrap();
    io.write_all(&[5, 0]).await.unwrap();
    let mut request = [0; 10];
    io.read_exact(&mut request).await.unwrap();
    assert_eq!(&request[..4], &[5, 1, 0, 1]);
    request[4..8].try_into().unwrap()
}

/// Answers the CONNECT and then the request inside the tunnel.
async fn tunnel(io: &mut tokio::net::TcpStream) {
    io.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 80])
        .await
        .unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        assert!(head.len() < 8192);
        head.push(io.read_u8().await.unwrap());
    }
    io.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        .await
        .unwrap();
}

/// Without a connect timeout, an address that answers after any length of
/// time is the connection: no other address is tried. With one, the stalled
/// case above shares it between the addresses.
#[test]
fn without_a_connect_timeout_an_address_is_not_given_up_for_the_next() {
    on_paused_clock(|| async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = reqwest::Client::builder()
            .proxy(
                reqwest::Proxy::all(format!("socks5://{}", listener.local_addr().unwrap()))
                    .unwrap(),
            )
            .resolve_to_addrs(
                "ordered.invalid",
                &[
                    "127.0.0.2:80".parse().unwrap(),
                    "127.0.0.1:80".parse().unwrap(),
                ],
            )
            .build()
            .unwrap();
        let server = async {
            let (mut io, _) = listener.accept().await.unwrap();
            assert_eq!(connect_request(&mut io).await, [127, 0, 0, 2]);
            // Longer than any fixed share would have let it take.
            tokio::time::advance(Duration::from_secs(60)).await;
            tunnel(&mut io).await;
            assert!(
                futures_util::FutureExt::now_or_never(listener.accept()).is_none(),
                "a second address was tried"
            );
        };
        let sending = async {
            let response = client.get("http://ordered.invalid/").send().await;
            assert_eq!(response.unwrap().bytes().await.unwrap().as_ref(), b"ok");
        };
        tokio::join!(sending, server);
    });
}
