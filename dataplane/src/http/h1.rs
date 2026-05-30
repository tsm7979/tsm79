/// HTTP/1.1 request and response parser — zero-copy state machine.
///
/// Parses from a raw byte buffer.  Header values are returned as byte slices
/// into the buffer to avoid allocation on the fast path.  The caller keeps
/// the buffer alive for as long as the parsed request is in use.
///
/// Supports:
///   - Content-Length bodies
///   - Transfer-Encoding: chunked bodies
///   - Keep-alive (Connection header)
///   - HTTP/1.0 and HTTP/1.1

// ── Public types ──────────────────────────────────────────────────────────────

/// A parsed HTTP/1.1 request with zero-copy header slices.
pub struct H1Request<'a> {
    pub method:       &'a [u8],
    pub path:         &'a [u8],
    pub version_minor: u8,              // 0 = HTTP/1.0, 1 = HTTP/1.1
    pub headers:      Vec<H1Header<'a>>,
    pub body:         &'a [u8],
}

/// A parsed HTTP/1.1 response.
pub struct H1Response<'a> {
    pub status:   u16,
    pub headers:  Vec<H1Header<'a>>,
    pub body:     &'a [u8],
    pub chunked:  bool,
}

/// A single HTTP header field.
pub struct H1Header<'a> {
    pub name:  &'a [u8],
    pub value: &'a [u8],
}

impl<'a> H1Header<'a> {
    /// Case-insensitive header name comparison.
    pub fn name_eq(&self, other: &str) -> bool {
        self.name.eq_ignore_ascii_case(other.as_bytes())
    }

    pub fn value_str(&self) -> &str {
        std::str::from_utf8(self.value).unwrap_or("")
    }
}

impl<'a> H1Request<'a> {
    /// Find the first header with the given name (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&H1Header<'a>> {
        self.headers.iter().find(|h| h.name_eq(name))
    }

    pub fn content_length(&self) -> Option<usize> {
        self.header("content-length")
            .and_then(|h| std::str::from_utf8(h.value).ok())
            .and_then(|v| v.trim().parse().ok())
    }

    pub fn is_chunked(&self) -> bool {
        self.header("transfer-encoding")
            .map(|h| h.value_str().to_lowercase().contains("chunked"))
            .unwrap_or(false)
    }

    pub fn keep_alive(&self) -> bool {
        self.version_minor == 1
            && !self
                .header("connection")
                .map(|h| h.value_str().to_lowercase().contains("close"))
                .unwrap_or(false)
    }
}

// ── Parse result ──────────────────────────────────────────────────────────────

pub enum ParseResult<'a> {
    /// Successfully parsed; `consumed` bytes were read from the front of buf.
    Complete(H1Request<'a>, usize),
    /// Not enough data yet.
    NeedMore,
    /// Protocol error.
    Error(&'static str),
}

pub enum ResponseParseResult<'a> {
    Complete(H1Response<'a>, usize),
    NeedMore,
    Error(&'static str),
}

// ── Parser ────────────────────────────────────────────────────────────────────

/// Parse one HTTP/1.1 request from `buf`.
///
/// The buffer must contain the full request headers.  If the body is
/// Content-Length delimited, the entire body must also be in `buf`.
/// For chunked bodies, pass `body_complete = false` and handle chunked
/// decoding separately.
pub fn parse_request(buf: &[u8]) -> ParseResult<'_> {
    // Find end of headers (\r\n\r\n)
    let header_end = match find_double_crlf(buf) {
        Some(pos) => pos,
        None      => return ParseResult::NeedMore,
    };

    let header_section = &buf[..header_end];
    let after_headers  = header_end + 4; // skip \r\n\r\n

    // Parse request line
    let (method, path, version_minor, line_end) = match parse_request_line(header_section) {
        Some(v) => v,
        None    => return ParseResult::Error("malformed request line"),
    };

    // Parse headers
    let mut headers = Vec::with_capacity(16);
    let mut cursor  = line_end + 2; // skip \r\n after request line
    loop {
        if cursor >= header_section.len() { break; }
        match parse_header_line(&buf[cursor..]) {
            Some((name, value, consumed)) => {
                headers.push(H1Header { name, value });
                cursor += consumed + 2; // +2 for \r\n
            }
            None => break,
        }
    }

    // Determine body slice
    let mut consumed = after_headers;
    let body_slice: &[u8];

    let is_chunked = headers.iter().any(|h|
        h.name_eq("transfer-encoding")
            && h.value_str().to_lowercase().contains("chunked")
    );

    if is_chunked {
        // Decode chunked body
        match decode_chunked(&buf[after_headers..]) {
            Some((decoded_end, _)) => {
                consumed = after_headers + decoded_end;
                body_slice = &buf[after_headers..after_headers]; // caller reads separately
            }
            None => return ParseResult::NeedMore,
        }
    } else {
        let content_length: usize = headers.iter()
            .find(|h| h.name_eq("content-length"))
            .and_then(|h| std::str::from_utf8(h.value).ok())
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);

        if buf.len() < after_headers + content_length {
            return ParseResult::NeedMore;
        }
        body_slice = &buf[after_headers..after_headers + content_length];
        consumed   = after_headers + content_length;
    }

    ParseResult::Complete(
        H1Request { method, path, version_minor, headers, body: body_slice },
        consumed,
    )
}

/// Parse one HTTP/1.1 response from `buf`.
pub fn parse_response(buf: &[u8]) -> ResponseParseResult<'_> {
    let header_end = match find_double_crlf(buf) {
        Some(pos) => pos,
        None      => return ResponseParseResult::NeedMore,
    };

    let header_section = &buf[..header_end];
    let after_headers  = header_end + 4;

    // Parse status line: "HTTP/1.x NNN Reason\r\n"
    let (status, line_end) = match parse_status_line(header_section) {
        Some(v) => v,
        None    => return ResponseParseResult::Error("malformed status line"),
    };

    let mut headers: Vec<H1Header> = Vec::with_capacity(16);
    let mut cursor = line_end + 2;
    loop {
        if cursor >= header_section.len() { break; }
        match parse_header_line(&buf[cursor..]) {
            Some((name, value, consumed)) => {
                headers.push(H1Header { name, value });
                cursor += consumed + 2;
            }
            None => break,
        }
    }

    let chunked = headers.iter().any(|h|
        h.name_eq("transfer-encoding")
            && h.value_str().to_lowercase().contains("chunked")
    );

    let (body, consumed) = if chunked {
        match decode_chunked(&buf[after_headers..]) {
            Some((end, _)) => (&buf[after_headers..after_headers], after_headers + end),
            None           => return ResponseParseResult::NeedMore,
        }
    } else {
        let cl: usize = headers.iter()
            .find(|h| h.name_eq("content-length"))
            .and_then(|h| std::str::from_utf8(h.value).ok())
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);
        if buf.len() < after_headers + cl {
            return ResponseParseResult::NeedMore;
        }
        (&buf[after_headers..after_headers + cl], after_headers + cl)
    };

    ResponseParseResult::Complete(H1Response { status, headers, body, chunked }, consumed)
}

/// Decode a chunked body in-place; returns `(bytes_consumed, decoded_length)`.
/// The caller must re-read `buf[..decoded_length]` for the actual body bytes.
pub fn decode_chunked(buf: &[u8]) -> Option<(usize, usize)> {
    let mut pos = 0;
    let mut decoded = 0;

    loop {
        // Find chunk size line ending \r\n
        let line_end = find_crlf(&buf[pos..])?;
        let size_str = std::str::from_utf8(&buf[pos..pos + line_end]).ok()?;
        // Strip chunk extensions (semicolon and beyond)
        let size_str = size_str.split(';').next().unwrap_or("").trim();
        let chunk_size = usize::from_str_radix(size_str, 16).ok()?;
        pos += line_end + 2; // skip \r\n

        if chunk_size == 0 {
            // Terminal chunk; consume trailing \r\n
            pos += find_crlf(&buf[pos..]).unwrap_or(0) + 2;
            return Some((pos, decoded));
        }

        if buf.len() < pos + chunk_size + 2 {
            return None; // need more data
        }
        decoded += chunk_size;
        pos     += chunk_size + 2; // skip chunk data + \r\n
    }
}

// ── Line parsing helpers ──────────────────────────────────────────────────────

fn parse_request_line(buf: &[u8]) -> Option<(&[u8], &[u8], u8, usize)> {
    let line_end  = find_crlf(buf)?;
    let line      = &buf[..line_end];
    let sp1       = line.iter().position(|&b| b == b' ')?;
    let method    = &line[..sp1];
    let rest      = &line[sp1 + 1..];
    let sp2       = rest.iter().position(|&b| b == b' ')?;
    let path      = &rest[..sp2];
    let version   = &rest[sp2 + 1..];
    let minor     = if version.ends_with(b"1.1") { 1 } else { 0 };
    Some((method, path, minor, line_end))
}

fn parse_status_line(buf: &[u8]) -> Option<(u16, usize)> {
    let line_end  = find_crlf(buf)?;
    let line      = &buf[..line_end];
    // "HTTP/1.x NNN ..."
    let sp1 = line.iter().position(|&b| b == b' ')?;
    let rest = &line[sp1 + 1..];
    let sp2  = rest.iter().position(|&b| b == b' ').unwrap_or(rest.len());
    let code = std::str::from_utf8(&rest[..sp2]).ok()?.trim().parse().ok()?;
    Some((code, line_end))
}

fn parse_header_line<'a>(buf: &'a [u8]) -> Option<(&'a [u8], &'a [u8], usize)> {
    if buf.starts_with(b"\r\n") {
        return None;
    }
    let line_end = find_crlf(buf)?;
    let line     = &buf[..line_end];
    let colon    = line.iter().position(|&b| b == b':')?;
    let name     = &line[..colon];
    let value    = line[colon + 1..].trim_ascii_start();
    Some((name, value, line_end))
}

// ── Byte-level search helpers ─────────────────────────────────────────────────

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

pub fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

// ── HTTP/1.1 response builder ─────────────────────────────────────────────────

/// Build a minimal HTTP/1.1 response.
pub fn build_response(status: u16, reason: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(128 + body.len());
    out.extend_from_slice(b"HTTP/1.1 ");
    out.extend_from_slice(status.to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(reason.as_bytes());
    out.extend_from_slice(b"\r\nContent-Type: ");
    out.extend_from_slice(content_type.as_bytes());
    out.extend_from_slice(b"\r\nContent-Length: ");
    out.extend_from_slice(body.len().to_string().as_bytes());
    out.extend_from_slice(b"\r\nConnection: keep-alive\r\n\r\n");
    out.extend_from_slice(body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIMPLE_POST: &[u8] = b"POST /v1/chat/completions HTTP/1.1\r\n\
        Host: localhost:8080\r\n\
        Content-Type: application/json\r\n\
        Content-Length: 13\r\n\
        \r\n\
        {\"test\":true}";

    #[test]
    fn parse_simple_post() {
        match parse_request(SIMPLE_POST) {
            ParseResult::Complete(req, consumed) => {
                assert_eq!(req.method, b"POST");
                assert_eq!(req.path, b"/v1/chat/completions");
                assert_eq!(req.version_minor, 1);
                assert_eq!(req.content_length(), Some(13));
                assert_eq!(req.body, b"{\"test\":true}");
                assert_eq!(consumed, SIMPLE_POST.len());
            }
            other => panic!("expected Complete, got different variant"),
        }
    }

    #[test]
    fn parse_returns_need_more_for_incomplete() {
        let partial = b"POST /v1/ HTTP/1.1\r\nContent-Length: 5\r\n\r\nab";
        assert!(matches!(parse_request(partial), ParseResult::NeedMore));
    }

    #[test]
    fn keep_alive_http11() {
        match parse_request(SIMPLE_POST) {
            ParseResult::Complete(req, _) => assert!(req.keep_alive()),
            _ => panic!("parse failed"),
        }
    }

    #[test]
    fn header_lookup_case_insensitive() {
        match parse_request(SIMPLE_POST) {
            ParseResult::Complete(req, _) => {
                assert!(req.header("content-type").is_some());
                assert!(req.header("CONTENT-TYPE").is_some());
                assert!(req.header("Content-Type").is_some());
            }
            _ => panic!("parse failed"),
        }
    }

    #[test]
    fn build_response_format() {
        let body = b"{\"error\":\"blocked\"}";
        let resp = build_response(400, "Bad Request", "application/json", body);
        assert!(resp.starts_with(b"HTTP/1.1 400 Bad Request\r\n"));
        assert!(resp.ends_with(body));
    }

    #[test]
    fn parse_response_200() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}";
        match parse_response(raw) {
            ResponseParseResult::Complete(res, consumed) => {
                assert_eq!(res.status, 200);
                assert_eq!(res.body, b"{}");
                assert_eq!(consumed, raw.len());
            }
            _ => panic!("parse failed"),
        }
    }
}
