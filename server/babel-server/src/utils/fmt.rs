

pub fn format_timestamp(ts: &str) -> String {
    // Parse RFC3339 format like "2026-02-13T22:34:19.056074500+00:00"
    // and return "2026-02-13 22:34:19"
    if let Some(pos) = ts.find('T') {
        if let Some(dot_pos) = ts.find('.') {
            format!("{} {}", &ts[..pos], &ts[pos + 1..dot_pos])
        } else if let Some(plus_pos) = ts.find('+') {
            format!("{} {}", &ts[..pos], &ts[pos + 1..plus_pos])
        } else {
            format!("{} {}", &ts[..pos], &ts[pos + 1..])
        }
    } else {
        ts.to_string()
    }
}