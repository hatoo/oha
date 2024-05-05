use futures::future::Future;
use futures::task::{Context, Poll};
use std::pin::Pin;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::{Arc, Mutex};
use std::task::Waker;

struct Inner {
    wakers: Mutex<Vec<Waker>>,
    set: AtomicBool,
}

#[derive(Clone)]
pub struct Flag(Arc<Inner>);

impl Flag {
    pub fn new() -> Self {
        Self(Arc::new(Inner {
            wakers: Mutex::new(Vec::new()),
            set: AtomicBool::new(false),
        }))
    }

    pub fn signal(&self) {
        self.0.set.store(true, Relaxed);

        std::mem::take::<Vec<Waker>>(self.0.wakers.lock().unwrap().as_mut())
            .into_iter()
            .for_each(|waker| waker.wake());
    }
}

impl Future for Flag {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.0.set.load(Relaxed) {
            // fast pass
            Poll::Ready(())
        } else {
            // Caring a case the `signal` is called and ended here. But it is very rare because `oha` calls `signal` after all initial `poll` is called.
            self.0.wakers.lock().unwrap().push(cx.waker().clone());
            if self.0.set.load(Relaxed) {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        }
    }
}
