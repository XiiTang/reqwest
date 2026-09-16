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
