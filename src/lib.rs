use anyhow::Context;
use aws_auth::AwsSignatureConfig;
use clap::Parser;
use crossterm::tty::IsTty;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use humantime::Duration;
use hyper::{
    HeaderMap,
    http::{
        self,
        header::{HeaderName, HeaderValue},
    },
};
use printer::{PrintConfig, PrintMode};
use rand_regex::Regex;
use ratatui::crossterm;
use result_data::ResultData;
use std::{
    env,
    fs::File,
    io::{BufRead, Read},
    path::{Path, PathBuf},
    pin::Pin,
    str::FromStr,
    sync::Arc,
};
use timescale::TimeScale;
use url::Url;
use url_generator::UrlGenerator;

mod aws_auth;
mod client;
#[cfg(feature = "http3")]
mod client_h3;
mod curl_compat;
mod db;
mod histogram;
mod monitor;
mod pcg64si;
mod printer;
mod result_data;
mod timescale;
mod tls_config;
mod url_generator;

#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[derive(Parser)]
#[command(version, about, long_about = None)]
#[command(arg_required_else_help(true))]
pub struct Opts {
    #[arg(help = "Target URL or file with multiple URLs.")]
    url: String,
    #[arg(
        help = "Number of requests to run.",
        short = 'n',
        default_value = "200"
    )]
    n_requests: usize,
    #[arg(
        help = "Number of connections to run concurrently. You may should increase limit to number of open files for larger `-c`.",
        short = 'c',
        default_value = "50"
    )]
    n_connections: usize,
    #[arg(
        help = "Number of parallel requests to send on HTTP/2. `oha` will run c * p concurrent workers in total.",
        short = 'p',
        default_value = "1"
    )]
    n_http2_parallel: usize,
    #[arg(
        help = "Duration of application to send requests. If duration is specified, n is ignored.
On HTTP/1, When the duration is reached, ongoing requests are aborted and counted as \"aborted due to deadline\"
You can change this behavior with `-w` option.
Currently, on HTTP/2, When the duration is reached, ongoing requests are waited. `-w` option is ignored.
Examples: -z 10s -z 3m.",
        short = 'z'
    )]
    duration: Option<Duration>,
    #[arg(
        help = "When the duration is reached, ongoing requests are waited",
        short,
        long,
        default_value = "false"
    )]
    wait_ongoing_requests_after_deadline: bool,
    #[arg(help = "Rate limit for all, in queries per second (QPS)", short = 'q')]
    query_per_second: Option<f64>,
    #[arg(
        help = "Introduce delay between a predefined number of requests.
Note: If qps is specified, burst will be ignored",
        long = "burst-delay"
    )]
    burst_duration: Option<Duration>,
    #[arg(
        help = "Rates of requests for burst. Default is 1
Note: If qps is specified, burst will be ignored",
        long = "burst-rate"
    )]
    burst_requests: Option<usize>,

    #[arg(
        help = "Generate URL by rand_regex crate but dot is disabled for each query e.g. http://127.0.0.1/[a-z][a-z][0-9]. Currently dynamic scheme, host and port with keep-alive do not work well. See https://docs.rs/rand_regex/latest/rand_regex/struct.Regex.html for details of syntax.",
        default_value = "false",
        long
    )]
    rand_regex_url: bool,

    #[arg(
        help = "Read the URLs to query from a file",
        default_value = "false",
        long
    )]
    urls_from_file: bool,

    #[arg(
        help = "A parameter for the '--rand-regex-url'. The max_repeat parameter gives the maximum extra repeat counts the x*, x+ and x{n,} operators will become.",
        default_value = "4",
        long
    )]
    max_repeat: u32,
    #[arg(
        help = "Dump target Urls <DUMP_URLS> times to debug --rand-regex-url",
        long
    )]
    dump_urls: Option<usize>,
    #[arg(
        help = "Correct latency to avoid coordinated omission problem. It's ignored if -q is not set.",
        long = "latency-correction"
    )]
    latency_correction: bool,
    #[arg(help = "No realtime tui", long = "no-tui")]
    no_tui: bool,
    #[arg(help = "Frame per second for tui.", default_value = "16", long = "fps")]
    fps: usize,
    #[arg(
        help = "HTTP method",
        short = 'm',
        long = "method",
        default_value = "GET"
    )]
    method: http::Method,
    #[arg(help = "Custom HTTP header. Examples: -H \"foo: bar\"", short = 'H')]
    headers: Vec<String>,
    #[arg(
        help = "Custom Proxy HTTP header. Examples: --proxy-header \"foo: bar\"",
        long = "proxy-header"
    )]
    proxy_headers: Vec<String>,
    #[arg(help = "Timeout for each request. Default to infinite.", short = 't')]
    timeout: Option<humantime::Duration>,
    #[arg(help = "HTTP Accept Header.", short = 'A')]
    accept_header: Option<String>,
    #[arg(help = "HTTP request body.", short = 'd')]
    body_string: Option<String>,
    #[arg(help = "HTTP request body from file.", short = 'D')]
    body_path: Option<std::path::PathBuf>,
    #[arg(help = "Content-Type.", short = 'T')]
    content_type: Option<String>,
    #[arg(
        help = "Basic authentication (username:password), or AWS credentials (access_key:secret_key)",
        short = 'a'
    )]
    basic_auth: Option<String>,
    #[arg(
        help = "Specify HTTP multipart POST data (curl compatible). Examples: -F 'name=value' -F 'file=@path/to/file'",
        short = 'F',
        long = "form"
    )]
    form: Vec<String>,
    #[arg(help = "AWS session token", long = "aws-session")]
    aws_session: Option<String>,
    #[arg(
        help = "AWS SigV4 signing params (format: aws:amz:region:service)",
        long = "aws-sigv4"
    )]
    aws_sigv4: Option<String>,
    #[arg(help = "HTTP proxy", short = 'x')]
    proxy: Option<Url>,
    #[arg(
        help = "HTTP version to connect to proxy. Available values 0.9, 1.0, 1.1, 2.",
        long = "proxy-http-version"
    )]
    proxy_http_version: Option<String>,
    #[arg(
        help = "Use HTTP/2 to connect to proxy. Shorthand for --proxy-http-version=2",
        long = "proxy-http2"
    )]
    proxy_http2: bool,
    #[arg(
        help = "HTTP version. Available values 0.9, 1.0, 1.1, 2, 3",
        long = "http-version"
    )]
    http_version: Option<String>,
    #[arg(help = "Use HTTP/2. Shorthand for --http-version=2", long = "http2")]
    http2: bool,
    #[arg(help = "HTTP Host header", long = "host")]
    host: Option<String>,
    #[arg(help = "Disable compression.", long = "disable-compression")]
    disable_compression: bool,
    #[arg(
        help = "Limit for number of Redirect. Set 0 for no redirection. Redirection isn't supported for HTTP/2.",
        default_value = "10",
        short = 'r',
        long = "redirect"
    )]
    redirect: usize,
    #[arg(
        help = "Disable keep-alive, prevents re-use of TCP connections between different HTTP requests. This isn't supported for HTTP/2.",
        long = "disable-keepalive"
    )]
    disable_keepalive: bool,
    #[arg(
        help = "*Not* perform a DNS lookup at beginning to cache it",
        long = "no-pre-lookup",
        default_value = "false"
    )]
    no_pre_lookup: bool,
    #[arg(help = "Lookup only ipv6.", long = "ipv6")]
    ipv6: bool,
    #[arg(help = "Lookup only ipv4.", long = "ipv4")]
    ipv4: bool,
    #[arg(
        help = "(TLS) Use the specified certificate file to verify the peer. Native certificate store is used even if this argument is specified.",
        long
    )]
    cacert: Option<PathBuf>,
    #[arg(
        help = "(TLS) Use the specified client certificate file. --key must be also specified",
        long
    )]
    cert: Option<PathBuf>,
    #[arg(
        help = "(TLS) Use the specified client key file. --cert must be also specified",
        long
    )]
    key: Option<PathBuf>,
    #[arg(help = "Accept invalid certs.", long = "insecure")]
    insecure: bool,
    #[arg(
        help = "Override DNS resolution and default port numbers with strings like 'example.org:443:localhost:8443'
Note: if used several times for the same host:port:target_host:target_port, a random choice is made",
        long = "connect-to"
    )]
    connect_to: Vec<ConnectToEntry>,
    #[arg(help = "Disable the color scheme.", long = "disable-color")]
    disable_color: bool,
    #[cfg(unix)]
    #[arg(
        help = "Connect to a unix socket instead of the domain in the URL. Only for non-HTTPS URLs.",
        long = "unix-socket",
        group = "socket-type"
    )]
    unix_socket: Option<std::path::PathBuf>,
    #[cfg(feature = "vsock")]
    #[arg(
        help = "Connect to a VSOCK socket using 'cid:port' instead of the domain in the URL. Only for non-HTTPS URLs.",
        long = "vsock-addr",
        group = "socket-type"
    )]
    vsock_addr: Option<VsockAddr>,
    #[arg(
        help = "Include a response status code successful or not successful breakdown for the time histogram and distribution statistics",
        long = "stats-success-breakdown"
    )]
    stats_success_breakdown: bool,
    #[arg(
        help = "Write succeeded requests to sqlite database url E.G test.db",
        long = "db-url"
    )]
    db_url: Option<String>,
    #[arg(
        long,
        help = "Perform a single request and dump the request and response"
    )]
    debug: bool,
    #[arg(
        help = "Output file to write the results to. If not specified, results are written to stdout.",
        long,
        short
    )]
    output: Option<PathBuf>,
    #[arg(help = "Output format", long, default_value = "text")]
    output_format: Option<PrintMode>,
    #[arg(
        help = "Time unit to be used. If not specified, the time unit is determined automatically. This option affects only text format.",
        long,
        short = 'u'
    )]
    time_unit: Option<TimeScale>,
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
struct VsockAddr(tokio_vsock::VsockAddr);

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

pub async fn run(mut opts: Opts) -> anyhow::Result<()> {
    let work_mode = opts.work_mode();

    // Parse AWS credentials from basic auth if AWS signing is requested
    let aws_config = if let Some(signing_params) = opts.aws_sigv4 {
        if let Some(auth) = &opts.basic_auth {
            let parts: Vec<&str> = auth.split(':').collect();
            if parts.len() != 2 {
                anyhow::bail!("Invalid AWS credentials format. Expected access_key:secret_key");
            }
            let access_key = parts[0];
            let secret_key = parts[1];
            let session_token = opts.aws_session.take();
            Some(AwsSignatureConfig::new(
                access_key,
                secret_key,
                &signing_params,
                session_token,
            )?)
        } else {
            anyhow::bail!("AWS credentials (--auth) required when using --aws-sigv4");
        }
    } else {
        None
    };

    let parse_http_version = |is_http2: bool, version: Option<&str>| match (is_http2, version) {
        (true, Some(_)) => anyhow::bail!("--http2 and --http-version are exclusive"),
        (true, None) => Ok(http::Version::HTTP_2),
        (false, Some(http_version)) => match http_version.trim() {
            "0.9" => Ok(http::Version::HTTP_09),
            "1.0" => Ok(http::Version::HTTP_10),
            "1.1" => Ok(http::Version::HTTP_11),
            "2.0" | "2" => Ok(http::Version::HTTP_2),
            #[cfg(feature = "http3")]
            "3.0" | "3" => Ok(http::Version::HTTP_3),
            #[cfg(not(feature = "http3"))]
            "3.0" | "3" => anyhow::bail!(
                "Your Oha instance has not been built with HTTP/3 support. Try recompiling with the feature enabled."
            ),
            _ => anyhow::bail!("Unknown HTTP version. Valid versions are 0.9, 1.0, 1.1, 2, 3"),
        },
        (false, None) => Ok(http::Version::HTTP_11),
    };

    let http_version: http::Version = parse_http_version(opts.http2, opts.http_version.as_deref())?;
    let proxy_http_version: http::Version =
        parse_http_version(opts.proxy_http2, opts.proxy_http_version.as_deref())?;

    let url_generator = if opts.rand_regex_url {
        // Almost URL has dot in domain, so disable dot in regex for convenience.
        let dot_disabled: String = opts
            .url
            .chars()
            .map(|c| {
                if c == '.' {
                    regex_syntax::escape(".")
                } else {
                    c.to_string()
                }
            })
            .collect();
        UrlGenerator::new_dynamic(Regex::compile(&dot_disabled, opts.max_repeat)?)
    } else if opts.urls_from_file {
        let path = Path::new(opts.url.as_str());
        let file = File::open(path)?;
        let reader = std::io::BufReader::new(file);

        let urls: Vec<Url> = reader
            .lines()
            .map_while(Result::ok)
            .filter(|line| !line.trim().is_empty())
            .map(|url_str| Url::parse(&url_str))
            .collect::<Result<Vec<_>, _>>()?;
        UrlGenerator::new_multi_static(urls)
    } else {
        UrlGenerator::new_static(Url::parse(&opts.url)?)
    };

    if let Some(n) = opts.dump_urls {
        let mut rng = rand::rng();
        for _ in 0..n {
            let url = url_generator.generate(&mut rng)?;
            println!("{url}");
        }
        return Ok(());
    }

    let url = url_generator.generate(&mut rand::rng())?;

    // Process form data or regular body first
    let has_form_data = !opts.form.is_empty();
    let (body, form_content_type): (Option<&'static [u8]>, Option<String>) = if has_form_data {
        // Handle form data (-F option)
        anyhow::ensure!(
            opts.body_string.is_none() && opts.body_path.is_none(),
            "Cannot use -F with -d or -D options"
        );

        let mut form = curl_compat::Form::new();

        for form_str in opts.form {
            let part: curl_compat::FormPart = form_str
                .parse()
                .with_context(|| format!("Failed to parse form data: {form_str}"))?;
            form.add_part(part);
        }

        let form_body = form.body();
        let content_type = form.content_type();

        (
            Some(Box::leak(form_body.into_boxed_slice())),
            Some(content_type),
        )
    } else {
        // Handle regular body data (-d or -D option)
        let body: Option<&'static [u8]> = match (opts.body_string, opts.body_path) {
            (Some(body), _) => Some(Box::leak(body.into_boxed_str().into_boxed_bytes())),
            (_, Some(path)) => {
                let mut buf = Vec::new();
                std::fs::File::open(path)?.read_to_end(&mut buf)?;
                Some(Box::leak(buf.into_boxed_slice()))
            }
            _ => None,
        };
        (body, None)
    };

    // Set method to POST if form data is used and method is GET
    let method = if has_form_data && opts.method == http::Method::GET {
        http::Method::POST
    } else {
        opts.method
    };

    let headers = {
        let mut headers: http::header::HeaderMap = Default::default();

        // Accept all
        headers.insert(
            http::header::ACCEPT,
            http::header::HeaderValue::from_static("*/*"),
        );

        // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Accept-Encoding
        if !opts.disable_compression {
            headers.insert(
                http::header::ACCEPT_ENCODING,
                http::header::HeaderValue::from_static("gzip, compress, deflate, br"),
            );
        }

        // User agent
        headers
            .entry(http::header::USER_AGENT)
            .or_insert(HeaderValue::from_static(concat!(
                "oha/",
                env!("CARGO_PKG_VERSION")
            )));

        if let Some(h) = opts.accept_header {
            headers.insert(http::header::ACCEPT, HeaderValue::from_bytes(h.as_bytes())?);
        }

        if let Some(h) = opts.content_type.or(form_content_type) {
            headers.insert(
                http::header::CONTENT_TYPE,
                HeaderValue::from_bytes(h.as_bytes())?,
            );
        }

        if let Some(h) = opts.host {
            headers.insert(http::header::HOST, HeaderValue::from_bytes(h.as_bytes())?);
        } else if http_version < http::Version::HTTP_2 {
            headers.insert(
                http::header::HOST,
                http::header::HeaderValue::from_str(url.authority())?,
            );
        }

        if let Some(auth) = opts.basic_auth {
            let u_p = auth.splitn(2, ':').collect::<Vec<_>>();
            anyhow::ensure!(u_p.len() == 2, anyhow::anyhow!("Parse auth"));
            let mut header_value = b"Basic ".to_vec();
            {
                use std::io::Write;
                let username = u_p[0];
                let password = if u_p[1].is_empty() {
                    None
                } else {
                    Some(u_p[1])
                };
                let mut encoder = base64::write::EncoderWriter::new(
                    &mut header_value,
                    &base64::engine::general_purpose::STANDARD,
                );
                // The unwraps here are fine because Vec::write* is infallible.
                write!(encoder, "{username}:").unwrap();
                if let Some(password) = password {
                    write!(encoder, "{password}").unwrap();
                }
            }

            headers.insert(
                http::header::AUTHORIZATION,
                HeaderValue::from_bytes(&header_value)?,
            );
        }

        if opts.disable_keepalive && http_version == http::Version::HTTP_11 {
            headers.insert(http::header::CONNECTION, HeaderValue::from_static("close"));
        }

        for (k, v) in opts
            .headers
            .into_iter()
            .map(|s| parse_header(s.as_str()))
            .collect::<anyhow::Result<Vec<_>>>()?
        {
            headers.insert(k, v);
        }

        headers
    };

    let proxy_headers = {
        opts.proxy_headers
            .into_iter()
            .map(|s| parse_header(s.as_str()))
            .collect::<anyhow::Result<HeaderMap<_>>>()?
    };

    let ip_strategy = match (opts.ipv4, opts.ipv6) {
        (false, false) => Default::default(),
        (true, false) => hickory_resolver::config::LookupIpStrategy::Ipv4Only,
        (false, true) => hickory_resolver::config::LookupIpStrategy::Ipv6Only,
        (true, true) => hickory_resolver::config::LookupIpStrategy::Ipv4AndIpv6,
    };
    let (config, mut resolver_opts) = system_resolv_conf()?;
    resolver_opts.ip_strategy = ip_strategy;
    let resolver = hickory_resolver::Resolver::builder_with_config(
        config,
        hickory_resolver::name_server::TokioConnectionProvider::default(),
    )
    .with_options(resolver_opts)
    .build();
    let cacert = opts.cacert.as_deref().map(std::fs::read).transpose()?;
    let client_auth = match (opts.cert, opts.key) {
        (Some(cert), Some(key)) => Some((std::fs::read(cert)?, std::fs::read(key)?)),
        (None, None) => None,
        // TODO: Ensure it on clap
        _ => anyhow::bail!("Both --cert and --key must be specified"),
    };

    let client = Arc::new(client::Client {
        aws_config,
        http_version,
        proxy_http_version,
        url_generator,
        method,
        headers,
        proxy_headers,
        body,
        dns: client::Dns {
            resolver,
            connect_to: opts.connect_to,
        },
        timeout: opts.timeout.map(|d| d.into()),
        redirect_limit: opts.redirect,
        disable_keepalive: opts.disable_keepalive,
        proxy_url: opts.proxy,
        #[cfg(unix)]
        unix_socket: opts.unix_socket,
        #[cfg(feature = "vsock")]
        vsock_addr: opts.vsock_addr.map(|v| v.0),
        #[cfg(feature = "rustls")]
        rustls_configs: tls_config::RuslsConfigs::new(
            opts.insecure,
            cacert.as_deref(),
            client_auth
                .as_ref()
                .map(|(cert, key)| (cert.as_slice(), key.as_slice())),
        ),
        #[cfg(all(feature = "native-tls", not(feature = "rustls")))]
        native_tls_connectors: tls_config::NativeTlsConnectors::new(
            opts.insecure,
            cacert.as_deref(),
            client_auth
                .as_ref()
                .map(|(cert, key)| (cert.as_slice(), key.as_slice())),
        ),
    });

    if !opts.no_pre_lookup {
        client.pre_lookup().await?;
    }

    let no_tui = opts.no_tui || !std::io::stdout().is_tty() || opts.debug;

    let print_config = {
        let mode = opts.output_format.unwrap_or_default();

        let disable_style =
            opts.disable_color || !std::io::stdout().is_tty() || opts.output.is_some();

        let output: Box<dyn std::io::Write + Send + 'static> = if let Some(output) = opts.output {
            Box::new(File::create(output)?)
        } else {
            Box::new(std::io::stdout())
        };

        PrintConfig {
            mode,
            output,
            disable_style,
            stats_success_breakdown: opts.stats_success_breakdown,
            time_unit: opts.time_unit,
        }
    };

    let run = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let start = std::time::Instant::now();

    let data_collect_future: Pin<Box<dyn std::future::Future<Output = (ResultData, PrintConfig)>>> =
        match work_mode {
            WorkMode::Debug => {
                let mut print_config = print_config;
                client::work_debug(&mut print_config.output, client).await?;
                return Ok(());
            }
            WorkMode::FixedNumber {
                n_requests,
                n_connections,
                n_http2_parallel,
                query_limit: None,
                latency_correction: _,
            } if no_tui => {
                // Use optimized worker of no_tui mode.
                let (result_tx, result_rx) = kanal::unbounded();

                client::fast::work(
                    client.clone(),
                    result_tx,
                    n_requests,
                    n_connections,
                    n_http2_parallel,
                )
                .await;

                Box::pin(async move {
                    let mut res = ResultData::default();
                    for r in result_rx {
                        res.merge(r);
                    }
                    (res, print_config)
                })
            }
            WorkMode::Until {
                duration,
                n_connections,
                n_http2_parallel,
                query_limit: None,
                latency_correction: _,
                wait_ongoing_requests_after_deadline,
            } if no_tui => {
                // Use optimized worker of no_tui mode.
                let (result_tx, result_rx) = kanal::unbounded();

                client::fast::work_until(
                    client.clone(),
                    result_tx,
                    start + duration,
                    n_connections,
                    n_http2_parallel,
                    wait_ongoing_requests_after_deadline,
                )
                .await;

                Box::pin(async move {
                    let mut res = ResultData::default();
                    for r in result_rx {
                        res.merge(r);
                    }
                    (res, print_config)
                })
            }
            mode => {
                let (result_tx, result_rx) = kanal::unbounded();
                let data_collector = if no_tui {
                    // When `--no-tui` is enabled, just collect all data.

                    let token = tokio_util::sync::CancellationToken::new();
                    let result_rx_ctrl_c = result_rx.clone();
                    let token_ctrl_c = token.clone();
                    let ctrl_c = tokio::spawn(async move {
                        tokio::select! {
                            _ = tokio::signal::ctrl_c() => {
                                let mut all: ResultData = Default::default();
                                let mut buf = Vec::new();
                                let _ = result_rx_ctrl_c.drain_into(&mut buf);
                                for res in buf {
                                    all.push(res);
                                }
                                let _ = printer::print_result(print_config, start, &all, start.elapsed());
                                std::process::exit(libc::EXIT_SUCCESS);
                            }
                            _ = token_ctrl_c.cancelled() => {
                                print_config
                            }

                        }
                    });

                    Box::pin(async move {
                        token.cancel();
                        let config = ctrl_c.await.unwrap();
                        let mut all = ResultData::default();
                        while let Ok(res) = result_rx.recv() {
                            all.push(res);
                        }
                        (all, config)
                    })
                        as Pin<Box<dyn std::future::Future<Output = (ResultData, PrintConfig)>>>
                } else {
                    // Spawn monitor future which draws realtime tui
                    let join_handle = tokio::spawn(
                        monitor::Monitor {
                            print_config,
                            end_line: opts
                                .duration
                                .map(|d| monitor::EndLine::Duration(d.into()))
                                .unwrap_or(monitor::EndLine::NumQuery(opts.n_requests)),
                            report_receiver: result_rx,
                            start,
                            fps: opts.fps,
                            disable_color: opts.disable_color,
                            time_unit: opts.time_unit,
                        }
                        .monitor(),
                    );

                    Box::pin(async { join_handle.await.unwrap().unwrap() })
                        as Pin<Box<dyn std::future::Future<Output = (ResultData, PrintConfig)>>>
                };

                match mode {
                    WorkMode::Debug => unreachable!("Must be already handled"),
                    WorkMode::FixedNumber {
                        n_requests,
                        n_connections,
                        n_http2_parallel,
                        query_limit,
                        latency_correction,
                    } => {
                        if let Some(query_limit) = query_limit {
                            if latency_correction {
                                client::work_with_qps(
                                    client.clone(),
                                    result_tx,
                                    query_limit,
                                    n_requests,
                                    n_connections,
                                    n_http2_parallel,
                                )
                                .await;
                            } else {
                                client::work_with_qps_latency_correction(
                                    client.clone(),
                                    result_tx,
                                    query_limit,
                                    n_requests,
                                    n_connections,
                                    n_http2_parallel,
                                )
                                .await;
                            }
                        } else {
                            client::work(
                                client.clone(),
                                result_tx,
                                n_requests,
                                n_connections,
                                n_http2_parallel,
                            )
                            .await;
                        }
                    }
                    WorkMode::Until {
                        duration,
                        n_connections,
                        n_http2_parallel,
                        query_limit,
                        latency_correction,
                        wait_ongoing_requests_after_deadline,
                    } => {
                        if let Some(query_limit) = query_limit {
                            if latency_correction {
                                client::work_until_with_qps_latency_correction(
                                    client.clone(),
                                    result_tx,
                                    query_limit,
                                    start,
                                    start + duration,
                                    n_connections,
                                    n_http2_parallel,
                                    wait_ongoing_requests_after_deadline,
                                )
                                .await;
                            } else {
                                client::work_until_with_qps(
                                    client.clone(),
                                    result_tx,
                                    query_limit,
                                    start,
                                    start + duration,
                                    n_connections,
                                    n_http2_parallel,
                                    wait_ongoing_requests_after_deadline,
                                )
                                .await;
                            }
                        } else {
                            client::work_until(
                                client.clone(),
                                result_tx,
                                start + duration,
                                n_connections,
                                n_http2_parallel,
                                wait_ongoing_requests_after_deadline,
                            )
                            .await;
                        }
                    }
                }

                data_collector
            }
        };

    let duration = start.elapsed();
    let (res, print_config) = data_collect_future.await;

    printer::print_result(print_config, start, &res, duration)?;

    if let Some(db_url) = opts.db_url {
        eprintln!("Storing results to {db_url}");
        db::store(&client, &db_url, start, res.success(), run)?;
    }

    Ok(())
}

fn system_resolv_conf() -> anyhow::Result<(ResolverConfig, ResolverOpts)> {
    // check if we are running in termux https://github.com/termux/termux-app
    #[cfg(unix)]
    if env::var("TERMUX_VERSION").is_ok() {
        let prefix = env::var("PREFIX")?;
        let path = format!("{prefix}/etc/resolv.conf");
        let conf_data = std::fs::read(&path).context(format!("DNS: failed to load {path}"))?;
        return hickory_resolver::system_conf::parse_resolv_conf(conf_data)
            .context(format!("DNS: failed to parse {path}"));
    }

    hickory_resolver::system_conf::read_system_conf()
        .context("DNS: failed to load /etc/resolv.conf")
}

enum WorkMode {
    Debug,
    FixedNumber {
        n_requests: usize,
        n_connections: usize,
        n_http2_parallel: usize,
        query_limit: Option<client::QueryLimit>,
        // ignored when query_limit is None
        latency_correction: bool,
    },
    Until {
        duration: std::time::Duration,
        n_connections: usize,
        n_http2_parallel: usize,
        query_limit: Option<client::QueryLimit>,
        // ignored when query_limit is None
        latency_correction: bool,
        wait_ongoing_requests_after_deadline: bool,
    },
}

impl Opts {
    fn work_mode(&self) -> WorkMode {
        if self.debug {
            WorkMode::Debug
        } else if let Some(duration) = self.duration {
            WorkMode::Until {
                duration: duration.into(),
                n_connections: self.n_connections,
                n_http2_parallel: self.n_http2_parallel,
                query_limit: match self.query_per_second {
                    Some(0f64) | None => self.burst_duration.map(|burst_duration| {
                        client::QueryLimit::Burst(
                            burst_duration.into(),
                            self.burst_requests.unwrap_or(1),
                        )
                    }),
                    Some(qps) => Some(client::QueryLimit::Qps(qps)),
                },
                latency_correction: self.latency_correction,
                wait_ongoing_requests_after_deadline: self.wait_ongoing_requests_after_deadline,
            }
        } else {
            WorkMode::FixedNumber {
                n_requests: self.n_requests,
                n_connections: self.n_connections,
                n_http2_parallel: self.n_http2_parallel,
                query_limit: match self.query_per_second {
                    Some(0f64) | None => self.burst_duration.map(|burst_duration| {
                        client::QueryLimit::Burst(
                            burst_duration.into(),
                            self.burst_requests.unwrap_or(1),
                        )
                    }),
                    Some(qps) => Some(client::QueryLimit::Qps(qps)),
                },
                latency_correction: self.latency_correction,
            }
        }
    }
}

fn parse_header(s: &str) -> Result<(HeaderName, HeaderValue), anyhow::Error> {
    let header = s.splitn(2, ':').collect::<Vec<_>>();
    anyhow::ensure!(header.len() == 2, anyhow::anyhow!("Parse header"));
    let name = HeaderName::from_str(header[0])?;
    let value = HeaderValue::from_str(header[1].trim_start_matches(' '))?;
    Ok::<(HeaderName, HeaderValue), anyhow::Error>((name, value))
}
