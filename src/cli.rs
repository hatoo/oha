pub fn parse_n_requests(s: &str) -> Result<usize, String> {
    let s = s.trim().to_lowercase();
    if let Some(num) = s.strip_suffix('k') {
        num.parse::<usize>().map(|n| n * 1000).map_err(|e| e.to_string())
    } else if let Some(num) = s.strip_suffix('m') {
        num.parse::<usize>().map(|n| n * 1000_000).map_err(|e| e.to_string())
    } else {
        s.parse::<usize>().map_err(|e| e.to_string())
    }
}
