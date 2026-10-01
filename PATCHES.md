# Boundless transport patch

Based on upstream `v0.13.4` (`11489b34eda6d32b15ad4033e62beba2ee401350`).
Retain upstream history and licenses; keep application behavior outside this fork.

`src/connect.rs` separates HTTPS proxy TLS from the origin's client identity.
The proxy config offers no client certificate, uses a separate resumption store,
retains the server verifier, and serves both HTTP forwarding and HTTPS CONNECT.
Origin mTLS inside CONNECT retains its identity and resumption store.

The hyper-util dependency is fixed at `0.1.20` so Boundless's root Cargo patch cannot
be bypassed by an ordinary dependency update. This fork does not change retries,
DNS policy, certificate trust or connection-pool recovery.

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

## Frozen proxy credential validity

Proxy::authorization_guard installs a caller-owned check in CONNECT and SOCKS5
connectors, and on each credential-bearing plain HTTP forwarding request.
The request guard travels into Hyper's actual H1/H2 dispatch, after connection
and readiness waits. It preserves the original rejection cause. It neither
adds retries nor applies expiry to response bodies or already authenticated
tunnels. Boundless tests cover queue, SOCKS greeting, proxy TLS waits, continued
response reading, and cache separation for equal credentials with different
validity metadata.

## Request dispatch guard and exact path

`RequestBuilder::dispatch_guard` installs a caller-owned check that Hyper runs
immediately before dispatching this request's head, after pool, connection and
readiness waits; a credential-bearing forwarding proxy's guard runs after it on
the same request. `RequestBuilder::exact_path` sends an absolute path exactly as
written, keeping `.`/`..` segments and their percent-encoded forms that `Url`
would resolve, while the URL keeps the scheme, authority and query. Boundless
uses both for origin credential expiry and for S3/OSS object keys. Run
`cargo test --test request_target`.
