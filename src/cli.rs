use hyper::http::header::{HeaderName, HeaderValue};
use std::str::FromStr;

pub fn parse_header(s: &str) -> Result<(HeaderName, HeaderValue), anyhow::Error> {
    let header = s.splitn(2, ':').collect::<Vec<_>>();
    anyhow::ensure!(header.len() == 2, anyhow::anyhow!("Parse header"));
    let name = HeaderName::from_str(header[0])?;
    let value = HeaderValue::from_str(header[1].trim_start_matches(' '))?;
    Ok::<(HeaderName, HeaderValue), anyhow::Error>((name, value))
}

pub fn parse_n_requests(s: &str) -> Result<usize, String> {
    let s = s.trim().to_lowercase();
    if let Some(num) = s.strip_suffix('k') {
        num.parse::<f64>()
            .map(|n| (n * 1000_f64) as usize)
            .map_err(|e| e.to_string())
    } else if let Some(num) = s.strip_suffix('m') {
        num.parse::<f64>()
            .map(|n| (n * 1_000_000_f64) as usize)
            .map_err(|e| e.to_string())
    } else {
        s.parse::<usize>().map_err(|e| e.to_string())
    }
}

/// An entry specified by `connect-to` to override DNS resolution and default
/// port numbers. For example, `example.org:80:localhost:5000` will connect to
/// `localhost:5000` whenever `http://example.org` is requested.
#[derive(Clone, Debug)]
pub struct ConnectToEntry {
    pub requested_host: String,
    pub requested_port: u16,
    pub target_host: String,
    pub target_port: u16,
}

impl FromStr for ConnectToEntry {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let expected_syntax: &str = "syntax for --connect-to is host:port:target_host:target_port";

        let (s, target_port) = s.rsplit_once(':').ok_or(expected_syntax)?;
        let (s, target_host) = if s.ends_with(']') {
            // ipv6
            let i = s.rfind(":[").ok_or(expected_syntax)?;
            (&s[..i], &s[i + 1..])
        } else {
            s.rsplit_once(':').ok_or(expected_syntax)?
        };
        let (requested_host, requested_port) = s.rsplit_once(':').ok_or(expected_syntax)?;

        Ok(ConnectToEntry {
            requested_host: requested_host.into(),
            requested_port: requested_port.parse().map_err(|err| {
                format!("requested port must be an u16, but got {requested_port}: {err}")
            })?,
            target_host: target_host.into(),
            target_port: target_port.parse().map_err(|err| {
                format!("target port must be an u16, but got {target_port}: {err}")
            })?,
        })
    }
}

/// A wrapper around a [`tokio_vsock::VsockAddr`] that provides a parser for clap
#[derive(Debug, Clone)]
#[repr(transparent)]
#[cfg(feature = "vsock")]
pub struct VsockAddr(pub tokio_vsock::VsockAddr);

#[cfg(feature = "vsock")]
impl FromStr for VsockAddr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (cid, port) = s
            .split_once(':')
            .ok_or("syntax for --vsock-addr is cid:port")?;
        Ok(Self(tokio_vsock::VsockAddr::new(
            cid.parse()
                .map_err(|err| format!("cid must be a u32, but got {cid}: {err}"))?,
            port.parse()
                .map_err(|err| format!("port must be a u32, but got {port}: {err}"))?,
        )))
    }
}
