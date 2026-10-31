#![cfg(not(target_arch = "wasm32"))]
#![cfg(not(feature = "rustls-no-provider"))]
mod support;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use support::server;

#[tokio::test]
async fn exact_target_keeps_dot_segments_and_query_octets() {
    let server = server::http(move |req| async move {
        assert_eq!(
            req.uri().path_and_query().unwrap().as_str(),
            "/bucket/folder/../%2E%2E/./file.txt?x-id=PutObject&name=O'Reilly&q=caf\u{e9}"
        );
        http::Response::default()
    });
    // The URL alone would send `/bucket/file.txt?...name=O%27Reilly&q=caf%C3%A9`.
    let url = format!(
        "http://{}/bucket/file.txt?x-id=PutObject&name=O'Reilly&q=caf\u{e9}",
        server.addr()
    );
    let response = reqwest::Client::new()
        .put(&url)
        .exact_path_and_query(
            "/bucket/folder/../%2E%2E/./file.txt?x-id=PutObject&name=O'Reilly&q=caf\u{e9}",
        )
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
}

#[tokio::test]
async fn exact_target_rejects_a_fragment_or_relative_path() {
    for path in ["bucket/file", "/bucket#f", "/bucket?x=1#f"] {
        let error = reqwest::Client::new()
            .get("http://127.0.0.1/")
            .exact_path_and_query(path)
            .send()
            .await
            .unwrap_err();
        assert!(error.is_builder(), "{path}");
    }
}

#[tokio::test]
async fn dispatch_guard_refuses_before_sending_and_permits_when_valid() {
    let received = Arc::new(AtomicUsize::new(0));
    let seen = received.clone();
    let server = server::http(move |_| {
        seen.fetch_add(1, Ordering::SeqCst);
        async { http::Response::default() }
    });
    let client = reqwest::Client::new();
    let url = format!("http://{}/", server.addr());
    let refused = client
        .get(&url)
        .dispatch_guard(|| Err::<(), _>("credential expired"))
        .send()
        .await
        .unwrap_err();
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&refused);
    let mut found = false;
    while let Some(error) = source {
        found |= error.to_string() == "credential expired";
        source = error.source();
    }
    assert!(found, "{refused:?}");
    assert_eq!(received.load(Ordering::SeqCst), 0);
    client
        .get(&url)
        .dispatch_guard(|| Ok::<(), &'static str>(()))
        .send()
        .await
        .unwrap();
    assert_eq!(received.load(Ordering::SeqCst), 1);
}
