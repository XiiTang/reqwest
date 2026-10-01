#![cfg(not(target_arch = "wasm32"))]
#![cfg(not(feature = "rustls-no-provider"))]
mod support;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use support::server;

#[tokio::test]
async fn exact_path_keeps_dot_segments_and_query() {
    let server = server::http(move |req| async move {
        assert_eq!(
            req.uri().path_and_query().unwrap().as_str(),
            "/bucket/folder/../%2E%2E/./file.txt?x-id=PutObject"
        );
        http::Response::default()
    });
    let url = format!("http://{}/bucket/file.txt?x-id=PutObject", server.addr());
    let response = reqwest::Client::new()
        .put(&url)
        .exact_path("/bucket/folder/../%2E%2E/./file.txt")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
}

#[tokio::test]
async fn exact_path_rejects_a_query_or_relative_path() {
    for path in ["bucket/file", "/bucket?x=1", "/bucket#f"] {
        let error = reqwest::Client::new()
            .get("http://127.0.0.1/")
            .exact_path(path)
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
