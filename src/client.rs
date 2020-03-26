use tokio::prelude::*;
use url::Url;

trait AsyncRW: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> AsyncRW for T {}

pub struct ClientBuilder {
    url: Url,
}

impl ClientBuilder {
    pub fn build(&self) -> Client {
        todo!()
    }
}

pub struct Client {
    url: Url,
    rng: rand::rngs::ThreadRng,
    resolver: Option<
        trust_dns_resolver::AsyncResolver<
            trust_dns_resolver::name_server::GenericConnection,
            trust_dns_resolver::name_server::GenericConnectionProvider<
                trust_dns_resolver::name_server::TokioRuntime,
            >,
        >,
    >,
    conn: Option<hyper::client::conn::SendRequest<hyper::Body>>,
}

impl Client {
    pub fn lookup_ip(&mut self) -> anyhow::Result<std::net::IpAddr> {
        todo!()
    }

    pub fn work(&mut self) -> anyhow::Result<crate::RequestResult> {
        todo!()
    }
}
