#![cfg(not(target_arch = "wasm32"))]

use std::{future::Future, pin::Pin};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type Work = Pin<Box<dyn Future<Output = ()> + Send>>;

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
    driver.await.unwrap();
}
