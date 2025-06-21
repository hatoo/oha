use std::{net::SocketAddr, sync::Arc};

use bytes::{Buf, Bytes};
use http::{Request, Response};
use kanal::Sender;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use h3::{quic::BidiStream, server::RequestStream};
use h3_quinn::quinn::{self, crypto::rustls::QuicServerConfig};

static ALPN: &[u8] = b"h3";

// This would be much cleaner if it took `process_request` as a callback, similar to the hyper service_fn.
pub async fn h3_server(
    tx: Sender<Request<Bytes>>,
    port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let listen = SocketAddr::new("127.0.0.1".parse().unwrap(), port);

    // Get the directory of the current file
    let current_file = file!();
    let current_dir = std::path::Path::new(current_file)
        .parent()
        .unwrap_or_else(|| std::path::Path::new(""));

    // Construct paths to cert and key files
    let cert_path = current_dir.join("server.cert");
    let key_path = current_dir.join("server.key");

    // both cert and key must be DER-encoded
    let cert = CertificateDer::from(std::fs::read(&cert_path)?);
    let key = PrivateKeyDer::try_from(std::fs::read(&key_path)?)?;

    let _ = rustls::crypto::CryptoProvider::install_default(
        rustls::crypto::aws_lc_rs::default_provider(),
    );
    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)?;

    tls_config.max_early_data_size = u32::MAX;
    tls_config.alpn_protocols = vec![ALPN.into()];

    let server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls_config)?));
    let endpoint = quinn::Endpoint::server(server_config, listen)?;

    // handle incoming connections and requests
    while let Some(new_conn) = endpoint.accept().await {
        let tx = tx.clone();

        let _ = tokio::spawn(async move {
            match new_conn.await {
                Ok(conn) => {
                    let mut h3_conn = h3::server::Connection::new(h3_quinn::Connection::new(conn))
                        .await
                        .unwrap();

                    loop {
                        let tx = tx.clone();
                        match h3_conn.accept().await {
                            Ok(Some(request_resolver)) => {
                                let (req, stream) =
                                    request_resolver.resolve_request().await.unwrap();
                                return process_request(req, stream, tx).await;
                            }

                            // indicating no more streams to be received
                            Ok(None) => {
                                return Ok(());
                            }

                            Err(_err) => {
                                unimplemented!()
                                // error!("error on accept {}", err);
                                /*
                                match err.get_error_level() {
                                    ErrorLevel::ConnectionError => break,
                                    ErrorLevel::StreamError => continue,
                                }
                                */
                            }
                        }
                    }
                }
                Err(_err) => Ok(()),
            }
        })
        .await?;
    }

    // shut down gracefully
    // wait for connections to be closed before exiting
    endpoint.wait_idle().await;

    Ok(())
}

async fn process_request<T>(
    req: Request<()>,
    mut stream: RequestStream<T, Bytes>,
    tx: Sender<Request<Bytes>>,
) -> Result<(), h3::error::StreamError>
where
    T: BidiStream<Bytes>,
{
    let (parts, _) = req.into_parts();
    let mut body_bytes = bytes::BytesMut::new();

    while let Some(mut chunk) = stream.recv_data().await? {
        let bytes = chunk.copy_to_bytes(chunk.remaining());
        body_bytes.extend_from_slice(&bytes);
    }
    let body = body_bytes.freeze();
    let req = Request::from_parts(parts, body);

    tx.send(req).unwrap();
    let resp = Response::new(());
    stream.send_response(resp).await?;
    stream.send_data("Hello world".into()).await?;
    stream.finish().await
}
