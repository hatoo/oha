use rusqlite::Connection;

use crate::client::{ClientError, RequestResult};

fn create_db(conn: &Connection) -> Result<usize, rusqlite::Error> {
    conn.execute(
        "CREATE TABLE loadtest (
            url TEXT NOT NULL,
            duration REAL,
            status INTEGER,
            len_bytes INTEGER
        )",
        (),
    )
}

pub fn store(
    db_url: &str,
    req_url: String,
    request_records: &[RequestResult],
) -> Result<usize, rusqlite::Error> {
    let conn = Connection::open(db_url)?;
    _ = create_db(&conn);

    let request_url = req_url
        .replace("https", "")
        .replace("http", "")
        .replace("://", "");

    let affected_rows =
        request_records
            .into_iter()
            .map(|req| {
                conn.execute(
          "INSERT INTO loadtest (url, duration, status, len_bytes) VALUES (?1, ?2, ?3, ?4)",
        (&request_url, req.duration().as_secs_f32(), req.status.as_u16() as u32, req.len_bytes),
        ).unwrap_or(0)
            })
            .sum();

    Ok(affected_rows)
}

#[cfg(test)]
mod test_db {
    use super::*;

    #[test]
    fn test_store() {
        let conn = Connection::open_in_memory().unwrap();
        let _ = create_db(&conn);
        let test_val = RequestResult {
            status: hyper::StatusCode::OK,
            len_bytes: 100,
            start_latency_correction: None,
            start: std::time::Instant::now(),
            connection_time: None,
            end: std::time::Instant::now(),
        };
        let test_vec = vec![test_val.clone(), test_val.clone()];
        let result = store("test.db", "test.com".to_owned(), &test_vec);
        assert_eq!(result.unwrap(), 2);
        std::fs::remove_file("test.db").unwrap();
    }
}
