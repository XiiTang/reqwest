#![cfg(not(target_arch = "wasm32"))]

use std::{future::Future, pin::Pin};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type Work = Pin<Box<dyn Future<Output = Result<(), BoxError>> + Send>>;

#[derive(Clone)]
struct Executor(tokio::sync::mpsc::UnboundedSender<Work>);
impl hyper::rt::Executor<Work> for Executor {
    fn execute(&self, future: Work) {
        self.0.send(future).unwrap();
    }
}

#[tokio::test]
async fn the_supplied_executor_drives_the_client_connection() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(stream.read_u8().await.unwrap());
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
    });
    let (send, mut work) = tokio::sync::mpsc::unbounded_channel();
    let client = reqwest::Client::builder()
        .no_proxy()
        .executor(Executor(send))
        .build()
        .unwrap();
    let response = tokio::spawn(async move {
        client
            .get(format!("http://{address}/"))
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap()
    });
    // The request cannot use a connection whose driver we have not run.
    let connection = tokio::time::timeout(std::time::Duration::from_secs(30), work.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(!response.is_finished());
    let driver = tokio::spawn(connection);
    assert_eq!(response.await.unwrap().as_ref(), b"ok");
    server.await.unwrap();
    driver.await.unwrap().unwrap();
}

#[tokio::test]
async fn the_supplied_executor_reads_a_background_failure_after_a_successful_response() {
    use std::{
        io,
        sync::{Arc, Mutex},
        task::{Context, Poll},
    };
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    struct Faulty {
        stream: tokio::io::DuplexStream,
        fault: tokio::sync::oneshot::Receiver<()>,
    }
    impl AsyncRead for Faulty {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if Pin::new(&mut self.fault).poll(cx).is_ready() {
                return Poll::Ready(Err(io::Error::other("reqwest background connection cause")));
            }
            Pin::new(&mut self.stream).poll_read(cx, buf)
        }
    }
    impl AsyncWrite for Faulty {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.stream).poll_write(cx, data)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.stream).poll_flush(cx)
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.stream).poll_shutdown(cx)
        }
    }
    let (stream, mut peer) = tokio::io::duplex(4096);
    let (fail, fault) = tokio::sync::oneshot::channel();
    let dial = Arc::new(Mutex::new(Some(Faulty { stream, fault })));
    let (send, mut work) = tokio::sync::mpsc::unbounded_channel();
    let client = reqwest::Client::builder()
        .no_proxy()
        .executor(Executor(send))
        .dialer(move |_| {
            let io = dial.lock().unwrap().take().unwrap();
            async move { Ok(io) }
        })
        .build()
        .unwrap();
    let server = tokio::spawn(async move {
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(peer.read_u8().await.unwrap());
        }
        peer.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        peer
    });
    let requester = client.clone();
    let response =
        tokio::spawn(async move { requester.get("http://fixture.test/").send().await.unwrap() });
    let connection = tokio::time::timeout(std::time::Duration::from_secs(30), work.recv())
        .await
        .unwrap()
        .unwrap();
    let driver = tokio::spawn(connection);
    let response = response.await.unwrap();
    let peer = server.await.unwrap();
    assert_eq!(response.status(), 200);
    fail.send(()).unwrap();
    let error = tokio::time::timeout(std::time::Duration::from_secs(30), driver)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(
        format!("{error:?}").contains("reqwest background connection cause"),
        "{error:?}"
    );
    assert_eq!(response.status(), 200);
    drop(client);
    drop(response);
    drop(peer);
    while let Ok(task) = work.try_recv() {
        task.await.unwrap();
    }
}
