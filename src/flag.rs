// Based on https://docs.rs/futures/latest/futures/task/struct.AtomicWaker.html
use futures::future::Future;
use futures::task::{AtomicWaker, Context, Poll};
use std::pin::Pin;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;

struct Inner {
    waker: AtomicWaker,
    set: AtomicBool,
}

#[derive(Clone)]
pub struct Flag(Arc<Inner>);

impl Default for Flag {
    fn default() -> Self {
        Self::new()
    }
}

impl Flag {
    pub fn new() -> Self {
        Self(Arc::new(Inner {
            waker: AtomicWaker::new(),
            set: AtomicBool::new(false),
        }))
    }

    pub fn signal(&self) {
        self.0.set.store(true, Relaxed);
        self.0.waker.wake();
    }

    pub fn is_signaled(&self) -> bool {
        self.0.set.load(Relaxed)
    }
}

impl<'a> Future for &'a Flag {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        // quick check to avoid registration if already done.
        if self.0.set.load(Relaxed) {
            return Poll::Ready(());
        }

        self.0.waker.register(cx.waker());

        // Need to check condition **after** `register` to avoid a race
        // condition that would result in lost notifications.
        if self.0.set.load(Relaxed) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}
