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
