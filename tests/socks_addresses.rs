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
