use anyhow::Context;
use rand::seq::SliceRandom;
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
    pub async fn lookup_ip(&mut self) -> anyhow::Result<std::net::IpAddr> {
        let resolver = if let Some(resolver) = self.resolver.take() {
            resolver
        } else {
            trust_dns_resolver::AsyncResolver::tokio(Default::default(), Default::default()).await?
        };

        let addrs = resolver
            .lookup_ip(self.url.host_str().context("get host")?)
            .await?
            .iter()
            .collect::<Vec<_>>();

        let addr = *addrs.choose(&mut self.rng).context("get addr")?;

        self.resolver = Some(resolver);

        Ok(addr)
    }

    pub fn work(&mut self) -> anyhow::Result<crate::RequestResult> {
        todo!()
    }
}
