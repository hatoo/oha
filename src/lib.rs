use anyhow::Context;
use aws_auth::AwsSignatureConfig;
use bytes::Bytes;
use clap::Parser;
use crossterm::tty::IsTty;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use humantime::Duration;
use hyper::{
    HeaderMap,
    http::{self, header::HeaderName, header::HeaderValue},
};
use printer::{PrintConfig, PrintMode};
use rand_regex::Regex;
use ratatui::crossterm;
use result_data::ResultData;
use std::{
    env,
    fs::File,
    io::{BufRead, BufReader, Read},
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
};
use timescale::TimeScale;
use url::Url;
use url_generator::UrlGenerator;

mod aws_auth;
mod cli;
mod client;
#[cfg(feature = "http3")]
mod client_h3;
mod curl_compat;
mod db;
mod histogram;
mod monitor;
mod pcg64si;
mod printer;
mod request_generator;
mod result_data;
mod timescale;
mod tls_config;
mod url_generator;

#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

use crate::{
    cli::{ConnectToEntry, parse_header},
    request_generator::{BodyGenerator, Proxy, RequestGenerator},
};

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

#[derive(Parser)]
#[command(version, about, long_about = None)]
#[command(arg_required_else_help(true))]
#[command(styles = clap_cargo::style::CLAP_STYLING)]
pub struct Opts {
    #[arg(help = "目标url或者包含多个url的文件.")]
    url: Option<String>,

    #[arg(long = "completions", hide = true)]
    pub completions: Option<clap_complete::Shell>,

    #[arg(
        help = "要发送的请求数量。支持数字后缀：k = 1,000，m = 1,000,000（例如 10k，1m）。[默认: 200].",
        short = 'n',
        default_value = "200",
        conflicts_with = "duration",
        value_parser = cli::parse_n_requests
    )]
    n_requests: usize,
    #[arg(
        help = "要发送的连接数。您可能需要增加限制以支持更大的 `-c`。",
        short = 'c',
        default_value = "50"
    )]
    n_connections: usize,
    #[arg(
        help = "要发送的并行请求数量。`oha` 将总共运行 c * p 个并发工作线程。",
        short = 'p',
        default_value = "1"
    )]
    n_http2_parallel: usize,
    #[arg(
        help = "发送请求的持续时间。
          在 HTTP/1 中，当达到持续时间后，正在进行的请求会被终止，
          并计为 “aborted due to deadline”（因超时截止被中止）。
          可以使用 `-w` 选项改变该行为。
          当前在 HTTP/2 中，当达到持续时间后，正在进行的请求会等待完成，
          `-w` 选项会被忽略。
          示例:
            -z 10s
            -z 3m",
        short = 'z',
        conflicts_with = "n_requests"
    )]
    duration: Option<Duration>,
    #[arg(
        help = "在达到持续时间后，等待正在进行的请求完成",
        short,
        long,
        default_value = "false",
        requires = "duration"
    )]
    wait_ongoing_requests_after_deadline: bool,
    #[arg(help = "所有请求的速率限制，单位为每秒查询次数(QPS)", short = 'q', conflicts_with_all = ["burst_duration", "burst_requests"])]
    query_per_second: Option<f64>,
    #[arg(
        help = "Introduce delay between a predefined number of requests.
Note: If qps is specified, burst will be ignored",
        long = "burst-delay",
        requires = "burst_requests",
        conflicts_with = "query_per_second"
    )]
    burst_duration: Option<Duration>,
    #[arg(
        help = "Rates of requests for burst. Default is 1
Note: If qps is specified, burst will be ignored",
        long = "burst-rate",
        requires = "burst_duration",
        conflicts_with = "query_per_second"
    )]
    burst_requests: Option<usize>,

    #[arg(
        help = "使用 rand_regex crate 生成 URL，但每个查询中的点被禁用。例如 http://127.0.0.1/[a-z][a-z][0-9]。目前动态方案、主机和端口与保持连接不兼容。详情请见 https://docs.rs/rand_regex/latest/rand_regex/struct.Regex.html。",
        default_value = "false",
        long
    )]
    rand_regex_url: bool,

    #[arg(
        help = "从文件中读取要查询的 URLs",
        default_value = "false",
        long
    )]
    urls_from_file: bool,

    #[arg(
        help = "`--rand-regex-url` 参数的最大重复次数用于 x*, x+, x{n,} 操作符。[默认: 4]",
        default_value = "4",
        long,
        requires = "rand_regex_url"
    )]
    max_repeat: u32,
    #[arg(
        help = "输出生成的 URL <DUMP_URLS> 次，用于调试 --rand-regex-url",
        long
    )]
    dump_urls: Option<usize>,
    #[arg(
        help = "修正延迟以避免 coordinated omission 问题如果未设置 -q，则该选项会被忽略",
        long = "latency-correction"
    )]
    latency_correction: bool,
    #[arg(help = "非实时 tui", long = "no-tui")]
    no_tui: bool,
    #[arg(help = " TUI帧率.", default_value = "16", long = "fps")]
    fps: usize,
    #[arg(
        help = "HTTP 方法",
        short = 'm',
        long = "method",
        default_value = "GET"
    )]
    method: http::Method,
    #[arg(help = "Custom HTTP header. Examples: -H \"foo: bar\"", short = 'H', value_parser = parse_header)]
    headers: Vec<(HeaderName, HeaderValue)>,
    #[arg(
        help = "Custom Proxy HTTP header. Examples: --proxy-header \"foo: bar\"",
        long = "proxy-header",
        value_parser = parse_header
    )]
    proxy_headers: Vec<(HeaderName, HeaderValue)>,
    #[arg(help = "Timeout for each request. Default to infinite.", short = 't')]
    timeout: Option<humantime::Duration>,
    #[arg(
        help = "Timeout for establishing a new connection. Default to 5s.",
        long = "connect-timeout",
        default_value = "5s"
    )]
    connect_timeout: humantime::Duration,
    #[arg(help = "HTTP 接受头.", short = 'A')]
    accept_header: Option<String>,
    #[arg(help = "HTTP 请求体.", short = 'd', conflicts_with_all = ["body_path", "body_path_lines", "form"])]
    body_string: Option<String>,
    #[arg(help = "HTTP 请求体来自文件.", short = 'D', conflicts_with_all = ["body_string", "body_path_lines", "form"])]
    body_path: Option<std::path::PathBuf>,
    #[arg(help = "HTTP 请求体来自文件，逐行读取.", short = 'Z', conflicts_with_all = ["body_string", "body_path", "form"])]
    body_path_lines: Option<std::path::PathBuf>,
    #[arg(
        help = "HTTP 表单数据. 格式与 curl 的 -F 选项相同，例如: -F \"field=value\" 或 -F \"file=@path/to/file\"",
        short = 'F',
        long = "form",
        conflicts_with_all = ["body_string", "body_path", "body_path_lines"]
    )]
    form: Vec<String>,
    #[arg(help = "链接类型.", short = 'T')]
    content_type: Option<String>,
    #[arg(
        help = "Basic 认证 (username:password), 或 AWS 凭证 (access_key:secret_key)",
        short = 'a'
    )]
    basic_auth: Option<String>,
    #[arg(help = "AWS 会话 token", long = "aws-session")]
    aws_session: Option<String>,
    #[arg(
        help = " AWS SigV4 签名参数，格式:aws:amz:region:service",
        long = "aws-sigv4"
    )]
    aws_sigv4: Option<String>,
    #[arg(help = "HTTP 代理", short = 'x')]
    proxy: Option<Url>,
    #[arg(
        help = "连接代理使用的 HTTP 版本可选:0.9, 1.0, 1.1, 2",
        long = "proxy-http-version"
    )]
    proxy_http_version: Option<String>,
    #[arg(
        help = "使用 HTTP/2 连接代理等同于:--proxy-http-version=2",
        long = "proxy-http2"
    )]
    proxy_http2: bool,
    #[arg(
        help = " HTTP 版本. 可选: 0.9, 1.0, 1.1, 2, 3",
        long = "http-version"
    )]
    http_version: Option<String>,
    #[arg(help = "使用 HTTP/2. 等同于: --http-version=2", long = "http2")]
    http2: bool,
    #[arg(help = "HTTP Host 头", long = "host")]
    host: Option<String>,
    #[arg(help = "禁用压缩.", long = "disable-compression")]
    disable_compression: bool,
    #[arg(
        help = "重定向最大次数设置 0 表示不允许重定向HTTP/2 不支持重定向 HTTP/2.",
        default_value = "10",
        short = 'r',
        long = "redirect"
    )]
    redirect: usize,
    #[arg(
        help = "禁用 keep-alive，防止在不同的 HTTP 请求之间重用 TCP 连接。此功能不支持 HTTP/2。",
        long = "disable-keepalive"
    )]
    disable_keepalive: bool,
    #[arg(
        help = "*不*在开始时执行 DNS 查找以缓存它",
        long = "no-pre-lookup",
        default_value = "false"
    )]
    no_pre_lookup: bool,
    #[arg(help = "仅解析 IPv6.", long = "ipv6")]
    ipv6: bool,
    #[arg(help = "仅解析 IPv4.", long = "ipv4")]
    ipv4: bool,
    #[arg(
        help = "(TLS) 使用指定证书验证服务器即使指定该参数，也会使用系统证书库.",
        long
    )]
    cacert: Option<PathBuf>,
    #[arg(
        help = "(TLS) 客户端证书文件必须同时指定 --key",
        long,
        requires = "key"
    )]
    cert: Option<PathBuf>,
    #[arg(
        help = "(TLS) 客户端私钥文件必须同时指定 --cert",
        long,
        requires = "cert"
    )]
    key: Option<PathBuf>,
    #[arg(help = "接受无效证书.", long = "insecure")]
    insecure: bool,
    #[arg(
        help = "覆盖 DNS 解析和默认端口格式:
            example.org:443:localhost:8443
          如果同一 host:port 指定多个目标，
          会随机选择",
        long = "connect-to"
    )]
    connect_to: Vec<ConnectToEntry>,
    #[arg(
        help = "禁用颜色方案.",
        alias = "disable-color",
        long = "no-color",
        env = "NO_COLOR"
    )]
    no_color: bool,
    #[cfg(unix)]
    #[arg(
        help = "通过 Unix Socket 连接仅适用于非 HTTPS URL.",
        long = "unix-socket",
        group = "socket-type"
    )]
    unix_socket: Option<std::path::PathBuf>,
    #[cfg(feature = "vsock")]
    #[arg(
        help = "Connect to a VSOCK socket using 'cid:port' instead of the domain in the URL. Only for non-HTTPS URLs.",
        long = "vsock-addr",
        value_parser = cli::parse_vsock_addr,
        group = "socket-type"
    )]
    vsock_addr: Option<tokio_vsock::VsockAddr>,
    #[arg(
        help = "在统计中显示成功请求的响应时间分布和直方图",
        long = "stats-success-breakdown"
    )]
    stats_success_breakdown: bool,
    #[arg(
        help = "将成功请求写入 sqlite 数据库示例:test.db",
        long = "db-url"
    )]
    db_url: Option<String>,
    #[arg(
        long,
        help = "发送单个请求并输出请求与响应"
    )]
    debug: bool,
    #[arg(
        help = "输出文件，用于写入结果。如果未指定，则结果将写入 stdout。",
        long,
        short
    )]
    output: Option<PathBuf>,
    #[arg(help = "输出格式", long, default_value = "text")]
    output_format: Option<PrintMode>,
    #[arg(
        help = "指定时间单位如果未指定，会自动选择仅影响 text 输出格式
          可选:
            ns
            us
            ms
            s
            m
            h
",
        long,
        short = 'u'
    )]
    time_unit: Option<TimeScale>,
}

pub async fn run(mut opts: Opts) -> anyhow::Result<()> {
    let work_mode = opts.work_mode();
    let url = opts.url.expect("URL is required");

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
        let dot_disabled: String = url
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
        let path = Path::new(url.as_str());
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
        UrlGenerator::new_static(Url::parse(&url)?)
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
    let (body_generator, form_content_type): (BodyGenerator, Option<String>) = if has_form_data {
        let mut form = curl_compat::Form::new();

        for form_str in opts.form {
            let part: curl_compat::FormPart = form_str
                .parse()
                .with_context(|| format!("Failed to parse form data: {form_str}"))?;
            form.add_part(part);
        }

        let form_body = form.body();
        let content_type = form.content_type();

        (BodyGenerator::Static(form_body.into()), Some(content_type))
    } else if let Some(body_string) = opts.body_string {
        (BodyGenerator::Static(body_string.into()), None)
    } else if let Some(body_path) = opts.body_path {
        let mut buf = Vec::new();
        std::fs::File::open(body_path)?.read_to_end(&mut buf)?;
        (BodyGenerator::Static(buf.into()), None)
    } else if let Some(body_path_lines) = opts.body_path_lines {
        let lines = BufReader::new(std::fs::File::open(body_path_lines)?)
            .lines()
            .map_while(Result::ok)
            .map(Bytes::from)
            .collect::<Vec<_>>();

        (BodyGenerator::Random(lines), None)
    } else {
        (BodyGenerator::Static(Bytes::new()), None)
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

        for (k, v) in opts.headers.into_iter() {
            headers.insert(k, v);
        }

        headers
    };

    let proxy_headers = opts.proxy_headers.into_iter().collect::<HeaderMap<_>>();

    let ip_strategy = match (opts.ipv4, opts.ipv6) {
        (false, false) => {
            if cfg!(target_os = "macos") && (url.host_str() == Some("localhost")) {
                // #784
                // On macOS, localhost resolves to ::1 first, So web servers that bind to localhost tend to listen ipv6 only.
                // So prefer ipv6 on macos for localhost.

                hickory_resolver::config::LookupIpStrategy::Ipv6thenIpv4
            } else {
                Default::default()
            }
        }
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
        // Not possible because of clap requires
        _ => anyhow::bail!("Both --cert and --key must be specified"),
    };

    let url = url.into_owned();
    let client = Arc::new(client::Client {
        request_generator: RequestGenerator {
            url_generator,
            https: url.scheme() == "https",
            version: http_version,
            aws_config,
            method,
            headers,
            body_generator,
            http_proxy: if opts.proxy.is_some() && url.scheme() == "http" {
                Some(Proxy {
                    headers: proxy_headers.clone(),
                    version: proxy_http_version,
                })
            } else {
                None
            },
        },
        proxy_http_version,
        proxy_headers,
        dns: client::Dns {
            resolver,
            connect_to: opts.connect_to,
        },
        timeout: opts.timeout.map(|d| d.into()),
        connect_timeout: opts.connect_timeout.into(),
        redirect_limit: opts.redirect,
        disable_keepalive: opts.disable_keepalive,
        proxy_url: opts.proxy,
        #[cfg(unix)]
        unix_socket: opts.unix_socket,
        #[cfg(feature = "vsock")]
        vsock_addr: opts.vsock_addr,
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

        let disable_style = opts.no_color || !std::io::stdout().is_tty() || opts.output.is_some();

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
                            disable_color: opts.no_color,
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
                                client::work_with_qps_latency_correction(
                                    client.clone(),
                                    result_tx,
                                    query_limit,
                                    n_requests,
                                    n_connections,
                                    n_http2_parallel,
                                )
                                .await;
                            } else {
                                client::work_with_qps(
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
        db::store(&client, &db_url, start, res.success(), run as i64)?;
    }

    Ok(())
}

pub(crate) fn system_resolv_conf() -> anyhow::Result<(ResolverConfig, ResolverOpts)> {
    // check if we are running in termux https://github.com/termux/termux-app
    #[cfg(unix)]
    if env::var("TERMUX_VERSION").is_ok() {
        let prefix = env::var("PREFIX")?;
        let path = format!("{prefix}/etc/resolv.conf");
        return match std::fs::read(&path) {
            Ok(conf_data) => hickory_resolver::system_conf::parse_resolv_conf(conf_data)
                .context(format!("DNS: failed to parse {path}")),
            Err(err) => {
                fallback_resolver_config(anyhow::anyhow!("DNS: failed to load {path}: {err}"))
            }
        };
    }

    match hickory_resolver::system_conf::read_system_conf() {
        Ok(conf) => Ok(conf),
        Err(err) => fallback_resolver_config(anyhow::anyhow!(
            "DNS: failed to load /etc/resolv.conf: {err}"
        )),
    }
}

fn fallback_resolver_config(err: anyhow::Error) -> anyhow::Result<(ResolverConfig, ResolverOpts)> {
    // Notify the user that we had to fall back to a default resolver configuration.
    eprintln!("{err}");

    let config = ResolverConfig::default();
    let opts = ResolverOpts::default();
    Ok((config, opts))
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
            let mut n_connections = self.n_connections;
            let max_useful = self.n_requests.div_ceil(self.n_http2_parallel);
            if n_connections > max_useful {
                n_connections = max_useful;
            }

            WorkMode::FixedNumber {
                n_requests: self.n_requests,
                n_connections,
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
