use futures::future::Future;
use futures::task::{AtomicWaker, Context, Poll};
use std::pin::Pin;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;

struct SignalFutureInner {
    waker: AtomicWaker,
    woken: Arc<AtomicBool>,
}

pub struct SignalFuture(Arc<SignalFutureInner>);

pub struct Signal {
    wakers: Vec<SignalFuture>,
    woken: Arc<AtomicBool>,
}

impl Signal {
    pub fn new() -> Self {
        Self {
            wakers: Vec::new(),
            woken: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn signal(self) {
        self.woken.store(true, Relaxed);

        for waker in self.wakers {
            waker.0.waker.wake();
        }
    }

    pub fn recv_signal(&mut self) -> SignalFuture {
        let inner = Arc::new(SignalFutureInner {
            waker: AtomicWaker::new(),
            woken: self.woken.clone(),
        });

        self.wakers.push(SignalFuture(inner.clone()));

        SignalFuture(inner)
    }
}

impl Future for SignalFuture {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        self.0.waker.register(cx.waker());

        if self.0.woken.load(Relaxed) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}
