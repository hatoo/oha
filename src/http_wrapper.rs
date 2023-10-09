use hyper::{body::Body, body::Incoming, Request, Response};
use std::task::{Context, Poll};

pub enum SendRequestX<B> {
    Http1(hyper::client::conn::http1::SendRequest<B>),
    Http2(hyper::client::conn::http2::SendRequest<B>),
}

impl<B> SendRequestX<B> {
    pub fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<hyper::Result<()>> {
        match self {
            SendRequestX::Http1(send) => send.poll_ready(cx),
            SendRequestX::Http2(send) => send.poll_ready(cx),
        }
    }
}

impl<B> SendRequestX<B>
where
    B: Body + 'static,
{
    pub async fn send_request(&mut self, req: Request<B>) -> hyper::Result<Response<Incoming>> {
        match self {
            SendRequestX::Http1(send) => send.send_request(req).await,
            SendRequestX::Http2(send) => send.send_request(req).await,
        }
    }
}

impl<B> SendRequestX<B> {
    pub fn http1(self) -> Option<hyper::client::conn::http1::SendRequest<B>> {
        match self {
            SendRequestX::Http1(send) => Some(send),
            SendRequestX::Http2(_) => None,
        }
    }

    pub fn http2(self) -> Option<hyper::client::conn::http2::SendRequest<B>> {
        match self {
            SendRequestX::Http1(_) => None,
            SendRequestX::Http2(send) => Some(send),
        }
    }
}
