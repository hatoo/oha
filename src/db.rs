use rusqlite::Connection;

use crate::client::{Client, RequestResult};

fn create_db(conn: &Connection) -> Result<usize, rusqlite::Error> {
    conn.execute(
        "CREATE TABLE oha (
            url TEXT NOT NULL,
            start REAL NOT NULL,
            start_latency_correction REAL,
            end REAL NOT NULL,
            duration REAL NOT NULL,
            status INTEGER NOT NULL,
            len_bytes INTEGER NOT NULL
        )",
        (),
    )
}

pub fn store(
    client: &Client,
    db_url: &str,
    start: std::time::Instant,
    request_records: &[RequestResult],
) -> Result<usize, rusqlite::Error> {
    let mut conn = Connection::open(db_url)?;
    create_db(&conn)?;

    let t = conn.transaction()?;
    let mut affected_rows = 0;

    for request in request_records {
        let url = client.generate_url(&mut request.rng.clone()).unwrap().0;
        affected_rows += t.execute(
            "INSERT INTO oha (url, start, start_latency_correction, end, duration, status, len_bytes) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            (
                url.to_string(),
                (request.start - start).as_secs_f64(),
                request.start_latency_correction.map(|d| (d - start).as_secs_f64()),
                (request.end - start).as_secs_f64(),
                request.duration().as_secs_f64(),
                request.status.as_u16() as i64,
                request.len_bytes,
            ),
        )?;
    }

    t.commit()?;

    Ok(affected_rows)
}

#[cfg(test)]
mod test_db {
    use hyper::{HeaderMap, Method, Version};
    use rand::SeedableRng;

    use crate::{client::Dns, url_generator::UrlGenerator};

    use super::*;

    #[test]
    fn test_store() {
        let start = std::time::Instant::now();
        let test_val = RequestResult {
            rng: SeedableRng::seed_from_u64(0),
            status: hyper::StatusCode::OK,
            len_bytes: 100,
            start_latency_correction: None,
            start: std::time::Instant::now(),
            connection_time: None,
            end: std::time::Instant::now(),
        };
        let test_vec = vec![test_val.clone(), test_val.clone()];
        let client = Client {
            http_version: Version::HTTP_11,
            proxy_http_version: Version::HTTP_11,
            url_generator: UrlGenerator::new_static("http://example.com".parse().unwrap()),
            method: Method::GET,
            headers: HeaderMap::new(),
            body: None,
            dns: Dns {
                resolver: hickory_resolver::AsyncResolver::tokio_from_system_conf().unwrap(),
                connect_to: Vec::new(),
            },
            timeout: None,
            redirect_limit: 0,
            disable_keepalive: false,
            insecure: false,
            proxy_url: None,
            #[cfg(unix)]
            unix_socket: None,
            #[cfg(feature = "vsock")]
            vsock_addr: None,
            #[cfg(feature = "rustls")]
            // Cache rustls_native_certs::load_native_certs() because it's expensive.
            root_cert_store: {
                let mut root_cert_store = rustls::RootCertStore::empty();
                for cert in
                    rustls_native_certs::load_native_certs().expect("could not load platform certs")
                {
                    root_cert_store.add(cert).unwrap();
                }
                std::sync::Arc::new(root_cert_store)
            },
        };
        let result = store(&client, ":memory:", start, &test_vec);
        assert_eq!(result.unwrap(), 2);
    }
}
