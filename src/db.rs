use rusqlite::Connection;

use crate::client::{Client, RequestResult};

fn create_db(conn: &Connection) -> Result<usize, rusqlite::Error> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS oha (
            url TEXT NOT NULL,
            start REAL NOT NULL,
            first_byte REAL,
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
    run: i64,
) -> Result<usize, rusqlite::Error> {
    let mut conn = Connection::open(db_url)?;
    create_db(&conn)?;

    let t = conn.transaction()?;
    let mut affected_rows = 0;

    for request in request_records {
        let req = client.generate_request(&mut request.rng.clone()).unwrap().1;
        let url = req.uri();
        affected_rows += t.execute(
            "INSERT INTO oha (url, start, first_byte, duration, status, len_bytes, run) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            (
                url.to_string(),
                (request.start - start).as_secs_f64(),
                request.first_byte().map(|fb| fb.as_secs_f64()),
                request.duration().as_secs_f64(),
                request.status.as_u16() as i64,
                request.len_bytes as i64,
                run ,
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
            .as_secs() as i64;
        let start = std::time::Instant::now();
        let test_val = RequestResult {
            rng: SeedableRng::seed_from_u64(0),
            status: hyper::StatusCode::OK,
            len_bytes: 100,
            start: std::time::Instant::now(),
            connection_time: None,
            first_byte: None,
            duration: 1000000,
        };
        let test_vec = vec![test_val.clone(), test_val.clone()];
        let client = Client::default();
        let result = store(&client, ":memory:", start, &test_vec, run);
        assert_eq!(result.unwrap(), 2);
    }
}
