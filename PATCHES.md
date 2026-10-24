# Boundless transport patch

Based on upstream `v0.13.4` (`11489b34eda6d32b15ad4033e62beba2ee401350`).
Retain upstream history and licenses; keep application behavior outside this fork.

## Caller-supplied HTTP executor (2026-10-15)

`ClientBuilder::executor(exec)` passes the caller's executor to hyper-util's
legacy client, so its connection and pool tasks have the same owner as the
requests. Its bound matches that client's builder:
`E: hyper::rt::Executor<Pin<Box<dyn Future<Output = ()> + Send>>> + Send + Sync + Clone + 'static`.
Storage is `Arc<dyn Executor<BoxSendFuture> + Send + Sync>`, behind a cloneable
forwarder as in hyper-util; the default remains `TokioExecutor`. This option
does not change reqwest's separate blocking runtime or HTTP/3 implementation.

On macOS arm64 with Rust 1.97.0 and Boundless's pinned hyper/hyper-util/h2,
`cargo test --locked --no-default-features --features rustls,socks,http2
--test executor --test dialer --test proxy_tls --test request_target` passes
all 8 tests (exit 0). The executor regression takes the connection future
without running it, observes the request still pending, then runs it and
receives the response. Restoring the old hard-coded Tokio executor makes
that regression fail (exit 101). Existing dialer, TLS identity/resumption,
dispatch-guard and exact-path regressions pass.

Strict `cargo clippy --all-targets --locked --no-default-features --features
rustls,socks,http2 -- -D warnings` remains blocked (exit 101) by pre-existing
library and library-test lints, including `connect.rs`'s `non_minimal_cfg` and
the upstream test modules' `mixed_attributes_style`. No lint suppression or
baseline repair is part of this patch.

`src/connect.rs` separates HTTPS proxy TLS from the origin's client identity.
The proxy config offers no client certificate, uses a separate resumption store,
retains the server verifier, and serves both HTTP forwarding and HTTPS CONNECT.
Origin mTLS inside CONNECT retains its identity and resumption store.

The hyper-util dependency is fixed at `0.1.20` so Boundless's root Cargo patch cannot
be bypassed by an ordinary dependency update. Connection retries are controlled
by `ClientBuilder::retry_canceled_requests`; their default, DNS policy and
certificate trust retain the upstream behavior.

Run the synthetic local TLS regression with:

```sh
cargo test --no-default-features --features rustls-no-provider --test proxy_tls
```

It checks both proxy paths, origin mTLS, proxy authentication and actual TLS session
resumption at both layers. The added CA and certificates exist only in the fixture.

Boundless consumes a full commit SHA. Before updating that pin, compare with the
upstream release, retain only still-needed changes, and run this regression plus
Boundless's transport tests. Remove the fork override when an official release
provides the same behavior and downstream regressions pass.

## Request dispatch guard and exact path

`RequestBuilder::dispatch_guard` installs a caller-owned check that Hyper runs
immediately before dispatching this request's head, after pool, connection and
readiness waits. `RequestBuilder::exact_path` sends an absolute path exactly as
written, keeping `.`/`..` segments and their percent-encoded forms that `Url`
would resolve, while the URL keeps the scheme, authority and query. Boundless
uses the guard to reserve a single-use upstream OAuth refresh token only when the
request is actually dispatched, and the exact path for S3/OSS object keys. Run
`cargo test --test request_target`.


## SOCKS local DNS address attempts (2026-10-14)

Local DNS considers every supported address (IPv4 and IPv6 for SOCKS5; IPv4 for
SOCKS4), opening a fresh proxy connection for each failed/stalled CONNECT. A
configured connect timeout is the only bound: before each of several address
attempts, the time it leaves is divided among the addresses that remain, as
hyper-util's `HttpConnector` divides its own between addresses. Without one, an
attempt is bounded by nothing but its own outcome, and the next address is tried
only after it fails; no fixed duration stands in for a timeout nobody declared.
Single-address and proxy-DNS behavior retain the existing timeout contract. The
proxy connector's TCP Happy Eyeballs still owns dialing the proxy endpoint. Never
bypass the proxy or replay HTTP bytes. Remote DNS (SOCKS4a/SOCKS5h) sends the
original hostname exactly once. Empty local answers fail rather than silently
delegating local DNS to the proxy.

`cargo test --no-default-features --features rustls,socks --test socks_addresses
--test request_target --test proxy_tls` passes with the Boundless hyper/hyper-util
and h2 patches. Wire tests cover IPv4/IPv6 rejection followed by success, a stalled
first attempt that shares a configured connect timeout, fresh sockets, application
bytes sent once, and remote DNS. On a paused clock, a first address that answers
after sixty seconds without a connect timeout is the connection and no second
address is dialed; the 2026-10-03 patch, which bounded each attempt to five
seconds, fails that test. TLS identity separation/resumption and per-request
dispatch regressions also pass.

## Caller-supplied connection dialer (2026-10-03)

`ClientBuilder::dialer` takes a function from the request URI to a byte stream
and uses that stream in place of TCP, as Go's `Transport.DialContext` does.
Boundless opens each stream through an SSH `direct-tcpip` channel when an
operation routes through an SSH jump connection. TLS for `https` runs over the
dialed stream with the client's own trust, identity and origin name; proxies,
local transports and DNS are not consulted, as with `unix_socket`. Pooled
connections are reused as for TCP. A dial error is the request's connection
error. The dialed stream needs only `Send`: `Dialed` reaches it through
`SyncWrapper`.

`cargo test --no-default-features --features rustls,socks --test dialer` covers
HTTP over a dialed stream with a proxy configured, pooled reuse, HTTPS with
client mTLS and origin-name verification, and a failed dial. `native-tls` and
the no-TLS build also compile.

## Caller-owned reused-connection retries (driver plan v23 W7a, Rule 8)

At 637d9d6, `src/async_impl/client.rs:974` builds hyper-util's legacy client
without setting or exposing its `retry_canceled_requests` option. The
hyper-util 66402f8 default is `true` (`client/legacy/client.rs:1034`),
independent of reqwest's policy layer (`src/async_impl/client.rs:1057-1059`).
Thus `retry(retry::never())` alone still permits an unrecorded connection
retry. This is the failure class governed here; no other resend policy is
changed.

Async and blocking `ClientBuilder::retry_canceled_requests(bool)` forward
the setting at the one legacy-client construction point. Its default
remains `true`, matching hyper-util and preserving existing clients. The
configuration is private and is set through that builder, so every legacy
client receives it. Boundless's attempt owner selects both
`retry(retry::never())` and `retry_canceled_requests(false)`. The paired
hyper-util patch exposes `Error::is_unstarted_on_reused_connection()`;
reqwest already retains that error in its source chain. No Execution or
per-attempt callback is introduced. Retry module and builder help explain
the two independent controls.

`tests/reused_connection_retry.rs` holds the native driver and retires it
after a second request is queued on the reused connection but before it is
taken. With the option off, no second dial or peer request occurs and the
source chain retains the unstarted fact. Without the new option, default
connection retry still makes a second dial and request even though the
reqwest policy is `never`. Ignoring the forwarded option reproduces the
regression (exit 101); the fixed test passes (exit 0). The complete suite
with the enabled feature set passes on macOS arm64, Rust 1.98.1:
334 tests, four ignored (exit 0); fmt passes (exit 0). Strict all-targets
clippy exits 101 with the original base's diagnostics, with no suppression or independent
repair. The W7a patch is carried independently of W4a completion forwarding.
