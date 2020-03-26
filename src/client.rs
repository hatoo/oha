use tokio::prelude::*;
use url::Url;

trait AsyncRW: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> AsyncRW for T {}

pub struct ClientBuilder {
    url: Url,
}

pub struct Client {
    url: Url,
    resolver: trust_dns_resolver::AsyncResolver<
        trust_dns_resolver::name_server::GenericConnection,
        trust_dns_resolver::name_server::GenericConnectionProvider<
            trust_dns_resolver::name_server::TokioRuntime,
        >,
    >,
    conn: Option<hyper::client::conn::SendRequest<hyper::Body>>,
}

impl Client {
    pub fn work(&mut self) -> anyhow::Result<crate::RequestResult> {
        todo!()
    }
}
