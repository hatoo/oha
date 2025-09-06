use rusqlite::Connection;

use crate::client::{Client, RequestResult};

fn create_db(conn: &Connection) -> Result<usize, rusqlite::Error> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS oha (
            url TEXT NOT NULL,
            start REAL NOT NULL,
            start_latency_correction REAL,
            end REAL NOT NULL,
            duration REAL NOT NULL,
            status INTEGER NOT NULL,
            len_bytes INTEGER NOT NULL,
            run INTEGER NOT NULL
        )",
        (),
    )
}

pub fn store(
    client: &Client,
    db_url: &str,
    start: std::time::Instant,
    request_records: &[RequestResult],
    run: u64,
) -> Result<usize, rusqlite::Error> {
    let mut conn = Connection::open(db_url)?;
    create_db(&conn)?;

    let t = conn.transaction()?;
    let mut affected_rows = 0;

    for request in request_records {
        let req = client.generate_request(&mut request.rng.clone()).unwrap().0;
        let url = req.uri();
        affected_rows += t.execute(
            "INSERT INTO oha (url, start, start_latency_correction, end, duration, status, len_bytes, run) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            (
                url.to_string(),
                (request.start - start).as_secs_f64(),
                request.start_latency_correction.map(|d| (d - start).as_secs_f64()),
                (request.end - start).as_secs_f64(),
                request.duration().as_secs_f64(),
                request.status.as_u16() as i64,
                request.len_bytes,
                run
            ),
        )?;
    }

    t.commit()?;

    Ok(affected_rows)
}

#[cfg(test)]
mod test_db {
    use rand::SeedableRng;

    use super::*;

    #[test]
    fn test_store() {
        let run = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let start = std::time::Instant::now();
        let test_val = RequestResult {
            rng: SeedableRng::seed_from_u64(0),
            status: hyper::StatusCode::OK,
            len_bytes: 100,
            start_latency_correction: None,
            start: std::time::Instant::now(),
            connection_time: None,
            first_byte: None,
            end: std::time::Instant::now(),
        };
        let test_vec = vec![test_val.clone(), test_val.clone()];
        let client = Client::default();
        let result = store(&client, ":memory:", start, &test_vec, run);
        assert_eq!(result.unwrap(), 2);
    }
}
