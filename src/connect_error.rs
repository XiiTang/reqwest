use super::{BoxError, Connected, Connection};
use http::Uri;
use hyper::rt::{Read, ReadBufCursor, Write};
use std::{
    error::Error,
    fmt,
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tower_service::Service;

/// The actual operation that returned a connection error.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum ConnectStage {
    /// Opening or preparing the underlying transport.
    Dial,
    /// Validating the TLS name or performing the TLS handshake.
    TlsSetup,
    /// Reading or writing an established TLS transport.
    TlsIo,
    /// Performing HTTP CONNECT.
    HttpConnect,
    /// Performing a SOCKS handshake.
    Socks,
    /// Resolving the target locally for SOCKS.
    TargetDns,
}

/// Immutable attribution on a returned connection error, with its original source.
#[derive(Debug)]
pub struct ConnectError {
    stage: ConnectStage,
    proxy: Option<Uri>,
    source: BoxError,
}
impl ConnectError {
    /// The operation which actually returned this error.
    pub fn stage(&self) -> ConnectStage {
        self.stage
    }
    /// The selected proxy, or `None` for the target.
    pub fn proxy(&self) -> Option<&Uri> {
        self.proxy.as_ref()
    }
    pub(super) fn wrap(stage: ConnectStage, proxy: Option<Uri>, source: BoxError) -> BoxError {
        // io::Error's ordinary source skips its payload, so inspect get_ref too.
        fn attributed(error: &(dyn Error + 'static)) -> bool {
            error.is::<ConnectError>()
                || error
                    .downcast_ref::<io::Error>()
                    .and_then(io::Error::get_ref)
                    .is_some_and(|inner| attributed(inner))
                || error.source().is_some_and(attributed)
        }
        if attributed(&*source) {
            source
        } else {
            Box::new(Self {
                stage,
                proxy,
                source,
            })
        }
    }
    fn io(stage: ConnectStage, proxy: Option<Uri>, error: io::Error) -> io::Error {
        io::Error::new(error.kind(), Self::wrap(stage, proxy, Box::new(error)))
    }
}
impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "connection {:?} failed", self.stage)
    }
}
impl Error for ConnectError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&*self.source)
    }
}

// Wrap both Ready and Call before entering an HTTPS backend; wrapping the
// backend again preserves those lower errors and marks only its own failures.
#[derive(Debug, Clone)]
pub(super) struct Attributed<C> {
    inner: C,
    stage: ConnectStage,
    proxy: Option<Uri>,
}
impl<C> Attributed<C> {
    pub(super) fn new(inner: C, stage: ConnectStage, proxy: Option<Uri>) -> Self {
        Self {
            inner,
            stage,
            proxy,
        }
    }
}
impl<C> Service<Uri> for Attributed<C>
where
    C: Service<Uri>,
    C::Error: Into<BoxError>,
    C::Future: Send + 'static,
    C::Response: 'static,
{
    type Response = C::Response;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, BoxError>> + Send>>;
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), BoxError>> {
        self.inner
            .poll_ready(cx)
            .map_err(|error| ConnectError::wrap(self.stage, self.proxy.clone(), error.into()))
    }
    fn call(&mut self, uri: Uri) -> Self::Future {
        let future = self.inner.call(uri);
        let (stage, proxy) = (self.stage, self.proxy.clone());
        Box::pin(async move {
            future
                .await
                .map_err(|error| ConnectError::wrap(stage, proxy, error.into()))
        })
    }
}

#[derive(Debug)]
pub(super) struct AttributedIo<T> {
    inner: T,
    proxy: Option<Uri>,
    tls: bool,
}
impl<T> AttributedIo<T> {
    pub(super) fn new(inner: T, proxy: Option<Uri>, tls: bool) -> Self {
        Self { inner, proxy, tls }
    }
}
impl<T: Read + Unpin> Read for AttributedIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        let proxy = self.proxy.clone();
        let tls = self.tls;
        Pin::new(&mut self.inner)
            .poll_read(cx, buf)
            .map_err(|error| {
                if tls {
                    ConnectError::io(ConnectStage::TlsIo, proxy, error)
                } else {
                    error
                }
            })
    }
}
impl<T: Write + Unpin> Write for AttributedIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let proxy = self.proxy.clone();
        let tls = self.tls;
        Pin::new(&mut self.inner)
            .poll_write(cx, buf)
            .map_err(|error| {
                if tls {
                    ConnectError::io(ConnectStage::TlsIo, proxy, error)
                } else {
                    error
                }
            })
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let proxy = self.proxy.clone();
        let tls = self.tls;
        Pin::new(&mut self.inner).poll_flush(cx).map_err(|error| {
            if tls {
                ConnectError::io(ConnectStage::TlsIo, proxy, error)
            } else {
                error
            }
        })
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let proxy = self.proxy.clone();
        let tls = self.tls;
        Pin::new(&mut self.inner)
            .poll_shutdown(cx)
            .map_err(|error| {
                if tls {
                    ConnectError::io(ConnectStage::TlsIo, proxy, error)
                } else {
                    error
                }
            })
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let proxy = self.proxy.clone();
        let tls = self.tls;
        Pin::new(&mut self.inner)
            .poll_write_vectored(cx, bufs)
            .map_err(|error| {
                if tls {
                    ConnectError::io(ConnectStage::TlsIo, proxy, error)
                } else {
                    error
                }
            })
    }
}
impl<T: Connection> Connection for AttributedIo<T> {
    fn connected(&self) -> Connected {
        self.inner.connected()
    }
}
#[cfg(feature = "__tls")]
impl<T: super::TlsInfoFactory> super::TlsInfoFactory for AttributedIo<T> {
    fn tls_info(&self) -> Option<crate::tls::TlsInfo> {
        self.inner.tls_info()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper_util::rt::TokioIo;
    #[derive(Debug)]
    struct Lower;
    impl fmt::Display for Lower {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("typed lower failure")
        }
    }
    impl Error for Lower {}
    #[derive(Clone)]
    struct Connector(u8);
    impl Service<Uri> for Connector {
        type Response = TokioIo<tokio::io::DuplexStream>;
        type Error = BoxError;
        type Future = std::future::Ready<Result<Self::Response, BoxError>>;
        fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), BoxError>> {
            Poll::Ready(if self.0 == 0 {
                Err(io::Error::other(Lower).into())
            } else {
                Ok(())
            })
        }
        fn call(&mut self, _: Uri) -> Self::Future {
            std::future::ready(if self.0 == 1 {
                Err(io::Error::other(Lower).into())
            } else {
                let (client, peer) = tokio::io::duplex(4096);
                drop(peer);
                Ok(TokioIo::new(client))
            })
        }
    }
    fn find<T: Error + 'static>(error: &(dyn Error + 'static)) -> Option<&T> {
        error
            .downcast_ref()
            .or_else(|| {
                error
                    .downcast_ref::<io::Error>()
                    .and_then(io::Error::get_ref)
                    .and_then(|inner| find(inner))
            })
            .or_else(|| error.source().and_then(find))
    }
    async fn backend<S>(make: impl Fn(Attributed<Connector>) -> S)
    where
        S: Service<Uri, Error = BoxError>,
        S::Future: Send + 'static,
        S::Response: 'static,
    {
        let proxy: Uri = "https://proxy.test:443".parse().unwrap();
        for mode in 0..3 {
            let lower = Attributed::new(Connector(mode), ConnectStage::Dial, Some(proxy.clone()));
            let mut service =
                Attributed::new(make(lower), ConnectStage::TlsSetup, Some(proxy.clone()));
            let result = if mode == 0 {
                std::future::poll_fn(|cx| service.poll_ready(cx))
                    .await
                    .err()
                    .unwrap()
            } else {
                service.call(proxy.clone()).await.err().unwrap()
            };
            drop(service);
            let marker =
                find::<ConnectError>(&*result).expect("returned context survives destruction");
            assert_eq!(marker.proxy(), Some(&proxy));
            if mode < 2 {
                assert!(matches!(marker.stage(), ConnectStage::Dial));
                assert!(find::<Lower>(&*result).is_some());
            } else {
                assert!(matches!(marker.stage(), ConnectStage::TlsSetup));
            }
        }
    }
    #[cfg(feature = "__native-tls")]
    #[tokio::test]
    async fn native_tls_keeps_lower_ready_call_and_its_own_handshake_errors() {
        let tls =
            tokio_native_tls::TlsConnector::from(native_tls_crate::TlsConnector::new().unwrap());
        backend(|lower| hyper_tls::HttpsConnector::from((lower, tls.clone()))).await;
    }
    #[cfg(feature = "__rustls")]
    #[tokio::test]
    async fn rustls_keeps_lower_ready_call_and_its_own_handshake_errors() {
        let tls = std::sync::Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth(),
        );
        backend(|lower| hyper_rustls::HttpsConnector::from((lower, tls.clone()))).await;
        let mut service = Attributed::new(
            hyper_rustls::HttpsConnector::from((
                Attributed::new(Connector(1), ConnectStage::Dial, None),
                tls,
            )),
            ConnectStage::TlsSetup,
            None,
        );
        let error = service
            .call("https://invalid_name/".parse().unwrap())
            .await
            .err()
            .unwrap();
        assert!(matches!(
            find::<ConnectError>(&*error).unwrap().stage(),
            ConnectStage::TlsSetup
        ));
        assert!(find::<Lower>(&*error).is_none());
    }
}
