use rusqlite::Connection;

use crate::client::RequestResult;

fn create_db(conn: &Connection) -> Result<usize, rusqlite::Error> {
    conn.execute(
        "CREATE TABLE oha (
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
    db_url: &str,
    start: std::time::Instant,
    request_records: &[RequestResult],
) -> Result<usize, rusqlite::Error> {
    let mut conn = Connection::open(db_url)?;
    create_db(&conn)?;

    let t = conn.transaction()?;
    let affected_rows =
        request_records
            .iter()
            .map(|req| {
                t.execute(
          "INSERT INTO oha (start, start_latency_correction, end, duration, status, len_bytes) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        ((req.start - start).as_secs_f64(), req.start_latency_correction.map(|d| (d-start).as_secs_f64()), (req.end - start).as_secs_f64(), req.duration().as_secs_f64(), req.status.as_u16() as i64, req.len_bytes)
        ).unwrap_or(0)
            })
            .sum();
    t.commit()?;

    Ok(affected_rows)
}

#[cfg(test)]
mod test_db {
    use super::*;

    #[test]
    fn test_store() {
        let start = std::time::Instant::now();
        let test_val = RequestResult {
            status: hyper::StatusCode::OK,
            len_bytes: 100,
            start_latency_correction: None,
            start: std::time::Instant::now(),
            connection_time: None,
            end: std::time::Instant::now(),
        };
        let test_vec = vec![test_val.clone(), test_val.clone()];
        let result = store(":memory:", start, &test_vec);
        assert_eq!(result.unwrap(), 2);
    }
}
