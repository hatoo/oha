// Ported from https://github.com/lnx-search/rewrk/pull/6
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::ReadBuf;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use std::io::{IoSlice, Result};

pub struct CustomTcpStream {
    inner: TcpStream,
    counter: Arc<AtomicUsize>,
}

impl CustomTcpStream {
    pub fn new(stream: TcpStream, counter: Arc<AtomicUsize>) -> Self {
        Self {
            inner: stream,
            counter,
        }
    }
}

impl AsyncRead for CustomTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);

        self.counter
            .fetch_add(buf.filled().len(), Ordering::Relaxed);

        result
    }
}

impl AsyncWrite for CustomTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}
