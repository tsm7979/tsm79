/// HTTP/2 frame parser and stream state machine — RFC 7540.
///
/// Implements:
///   - 9-byte frame header parsing
///   - Frame types: DATA, HEADERS, PRIORITY, RST_STREAM, SETTINGS,
///     PUSH_PROMISE, PING, GOAWAY, WINDOW_UPDATE, CONTINUATION
///   - Stream state machine per RFC 7540 §5.1
///   - SETTINGS negotiation (initial frame exchange)
///   - HPACK integration for HEADERS frames
///   - WINDOW_UPDATE flow control tracking

use std::collections::HashMap;
use super::hpack::HpackDecoder;

// ── Constants ─────────────────────────────────────────────────────────────────

pub const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
pub const FRAME_HEADER_LEN: usize = 9;
pub const DEFAULT_INITIAL_WINDOW: u32 = 65535;
pub const DEFAULT_MAX_FRAME_SIZE: u32 = 16384;

// Frame type constants
pub const FRAME_DATA:          u8 = 0x0;
pub const FRAME_HEADERS:       u8 = 0x1;
pub const FRAME_PRIORITY:      u8 = 0x2;
pub const FRAME_RST_STREAM:    u8 = 0x3;
pub const FRAME_SETTINGS:      u8 = 0x4;
pub const FRAME_PUSH_PROMISE:  u8 = 0x5;
pub const FRAME_PING:          u8 = 0x6;
pub const FRAME_GOAWAY:        u8 = 0x7;
pub const FRAME_WINDOW_UPDATE: u8 = 0x8;
pub const FRAME_CONTINUATION:  u8 = 0x9;

// Flags
pub const FLAG_END_STREAM:    u8 = 0x1;
pub const FLAG_END_HEADERS:   u8 = 0x4;

// HTTP/2 error codes (RFC 7540 §7)
pub const ERR_STREAM_CLOSED:  u32 = 0x5;
pub const FLAG_PADDED:        u8 = 0x8;
pub const FLAG_PRIORITY:      u8 = 0x20;
pub const FLAG_ACK:           u8 = 0x1;

// SETTINGS identifiers
pub const SETTINGS_HEADER_TABLE_SIZE:      u16 = 0x1;
pub const SETTINGS_ENABLE_PUSH:            u16 = 0x2;
pub const SETTINGS_MAX_CONCURRENT_STREAMS: u16 = 0x3;
pub const SETTINGS_INITIAL_WINDOW_SIZE:    u16 = 0x4;
pub const SETTINGS_MAX_FRAME_SIZE:         u16 = 0x5;
pub const SETTINGS_MAX_HEADER_LIST_SIZE:   u16 = 0x6;

// Error codes
pub const ERR_NO_ERROR:           u32 = 0x0;
pub const ERR_PROTOCOL_ERROR:     u32 = 0x1;
pub const ERR_FLOW_CONTROL_ERROR: u32 = 0x3;
pub const ERR_FRAME_SIZE_ERROR:   u32 = 0x6;
pub const ERR_COMPRESSION_ERROR:  u32 = 0x9;

// ── Frame types ───────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct FrameHeader {
    pub length:    u32,   // 24-bit
    pub frame_type: u8,
    pub flags:     u8,
    pub stream_id: u32,   // 31-bit (MSB reserved, masked out)
}

impl FrameHeader {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < FRAME_HEADER_LEN {
            return None;
        }
        let length     = (buf[0] as u32) << 16 | (buf[1] as u32) << 8 | buf[2] as u32;
        let frame_type = buf[3];
        let flags      = buf[4];
        let stream_id  = ((buf[5] as u32) << 24 | (buf[6] as u32) << 16
                        | (buf[7] as u32) << 8  | buf[8] as u32) & 0x7fff_ffff;
        Some(FrameHeader { length, frame_type, flags, stream_id })
    }

    pub fn serialize(&self) -> [u8; FRAME_HEADER_LEN] {
        let mut out = [0u8; FRAME_HEADER_LEN];
        out[0] = (self.length >> 16) as u8;
        out[1] = (self.length >> 8)  as u8;
        out[2] =  self.length        as u8;
        out[3] = self.frame_type;
        out[4] = self.flags;
        out[5] = (self.stream_id >> 24) as u8;
        out[6] = (self.stream_id >> 16) as u8;
        out[7] = (self.stream_id >> 8)  as u8;
        out[8] =  self.stream_id        as u8;
        out
    }
}

// ── H2 events emitted by the parser ──────────────────────────────────────────

#[derive(Debug)]
pub enum H2Event {
    /// A complete set of headers for a stream.
    Headers {
        stream_id:  u32,
        headers:    Vec<(Vec<u8>, Vec<u8>)>,
        end_stream: bool,
    },
    /// A data chunk for a stream.
    Data {
        stream_id:  u32,
        data:       Vec<u8>,
        end_stream: bool,
    },
    /// Remote sent SETTINGS; we should ACK.
    Settings { ack: bool },
    /// Remote sent PING; we should PONG.
    Ping { data: [u8; 8], ack: bool },
    /// Remote closed a stream with RST_STREAM.
    ResetStream { stream_id: u32, error_code: u32 },
    /// Connection-level GOAWAY.
    GoAway { last_stream: u32, error_code: u32 },
    /// Flow control window update.
    WindowUpdate { stream_id: u32, increment: u32 },
    /// Need more data.
    NeedMore,
    /// Protocol error.
    Error { code: u32, msg: &'static str },
}

// ── Stream state ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum StreamState {
    Idle,
    Open,
    HalfClosedLocal,
    HalfClosedRemote,
    Closed,
}

struct H2Stream {
    state:          StreamState,
    window:         i64,   // flow control window
    pending_headers: Vec<u8>,  // buffered HEADERS fragment for CONTINUATION
}

// ── Connection parser ─────────────────────────────────────────────────────────

pub struct H2Conn {
    pub hpack:          HpackDecoder,
    streams:            HashMap<u32, H2Stream>,
    pub local_settings: H2Settings,
    pub peer_settings:  H2Settings,
    conn_window:        i64,
    header_table_size:  usize,
    continuation_sid:   u32,  // stream awaiting CONTINUATION frames
}

#[derive(Clone)]
pub struct H2Settings {
    pub header_table_size:      usize,
    pub enable_push:            bool,
    pub max_concurrent_streams: u32,
    pub initial_window_size:    u32,
    pub max_frame_size:         u32,
    pub max_header_list_size:   u32,
}

impl Default for H2Settings {
    fn default() -> Self {
        H2Settings {
            header_table_size:      4096,
            enable_push:            true,
            max_concurrent_streams: u32::MAX,
            initial_window_size:    DEFAULT_INITIAL_WINDOW,
            max_frame_size:         DEFAULT_MAX_FRAME_SIZE,
            max_header_list_size:   u32::MAX,
        }
    }
}

impl H2Conn {
    pub fn new() -> Self {
        H2Conn {
            hpack:           HpackDecoder::new(4096),
            streams:         HashMap::new(),
            local_settings:  H2Settings::default(),
            peer_settings:   H2Settings::default(),
            conn_window:     DEFAULT_INITIAL_WINDOW as i64,
            header_table_size: 4096,
            continuation_sid: 0,
        }
    }

    /// Build the server's initial SETTINGS frame payload.
    pub fn server_settings_frame() -> Vec<u8> {
        // Emit: HEADER_TABLE_SIZE=4096, MAX_CONCURRENT_STREAMS=100, MAX_FRAME_SIZE=16384
        let params: &[(u16, u32)] = &[
            (SETTINGS_HEADER_TABLE_SIZE,      4096),
            (SETTINGS_MAX_CONCURRENT_STREAMS, 100),
            (SETTINGS_MAX_FRAME_SIZE,         16384),
        ];
        let payload_len = params.len() * 6;
        let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + payload_len);
        frame.extend_from_slice(&FrameHeader {
            length:     payload_len as u32,
            frame_type: FRAME_SETTINGS,
            flags:      0,
            stream_id:  0,
        }.serialize());
        for &(id, val) in params {
            frame.push((id >> 8) as u8);
            frame.push(id as u8);
            frame.push((val >> 24) as u8);
            frame.push((val >> 16) as u8);
            frame.push((val >> 8)  as u8);
            frame.push(val         as u8);
        }
        frame
    }

    /// Build a SETTINGS ACK frame.
    pub fn settings_ack_frame() -> Vec<u8> {
        FrameHeader {
            length:     0,
            frame_type: FRAME_SETTINGS,
            flags:      FLAG_ACK,
            stream_id:  0,
        }.serialize().to_vec()
    }

    /// Build a PING ACK frame.
    pub fn ping_ack_frame(data: [u8; 8]) -> Vec<u8> {
        let mut out = FrameHeader {
            length:     8,
            frame_type: FRAME_PING,
            flags:      FLAG_ACK,
            stream_id:  0,
        }.serialize().to_vec();
        out.extend_from_slice(&data);
        out
    }

    /// Build a WINDOW_UPDATE frame.
    pub fn window_update_frame(stream_id: u32, increment: u32) -> Vec<u8> {
        let mut out = FrameHeader {
            length:     4,
            frame_type: FRAME_WINDOW_UPDATE,
            flags:      0,
            stream_id,
        }.serialize().to_vec();
        out.push((increment >> 24) as u8);
        out.push((increment >> 16) as u8);
        out.push((increment >> 8)  as u8);
        out.push(increment         as u8);
        out
    }

    /// Parse the next event from `buf`.  Returns the event and bytes consumed.
    pub fn process(&mut self, buf: &[u8]) -> (H2Event, usize) {
        if buf.len() < FRAME_HEADER_LEN {
            return (H2Event::NeedMore, 0);
        }
        let hdr = match FrameHeader::parse(buf) {
            Some(h) => h,
            None    => return (H2Event::NeedMore, 0),
        };
        let total = FRAME_HEADER_LEN + hdr.length as usize;
        if buf.len() < total {
            return (H2Event::NeedMore, 0);
        }
        let payload = &buf[FRAME_HEADER_LEN..total];
        let event   = self.dispatch(&hdr, payload);
        (event, total)
    }

    fn dispatch(&mut self, hdr: &FrameHeader, payload: &[u8]) -> H2Event {
        // Enforce max frame size
        if hdr.length > self.peer_settings.max_frame_size {
            return H2Event::Error { code: ERR_FRAME_SIZE_ERROR, msg: "frame too large" };
        }

        match hdr.frame_type {
            FRAME_SETTINGS      => self.handle_settings(hdr, payload),
            FRAME_HEADERS       => self.handle_headers(hdr, payload),
            FRAME_DATA          => self.handle_data(hdr, payload),
            FRAME_PING          => self.handle_ping(hdr, payload),
            FRAME_WINDOW_UPDATE => self.handle_window_update(hdr, payload),
            FRAME_RST_STREAM    => self.handle_rst(hdr, payload),
            FRAME_GOAWAY        => self.handle_goaway(payload),
            FRAME_CONTINUATION  => self.handle_continuation(hdr, payload),
            FRAME_PRIORITY      => H2Event::NeedMore, // ignore priority hints
            FRAME_PUSH_PROMISE  => H2Event::Error { code: ERR_PROTOCOL_ERROR, msg: "client sent PUSH_PROMISE" },
            _                   => H2Event::NeedMore, // unknown frame type — ignore
        }
    }

    fn handle_settings(&mut self, hdr: &FrameHeader, payload: &[u8]) -> H2Event {
        let ack = hdr.flags & FLAG_ACK != 0;
        if ack {
            return H2Event::Settings { ack: true };
        }
        // Parse setting pairs (6 bytes each)
        if payload.len() % 6 != 0 {
            return H2Event::Error { code: ERR_FRAME_SIZE_ERROR, msg: "SETTINGS frame bad length" };
        }
        for chunk in payload.chunks(6) {
            let id  = (chunk[0] as u16) << 8 | chunk[1] as u16;
            let val = (chunk[2] as u32) << 24 | (chunk[3] as u32) << 16
                    | (chunk[4] as u32) << 8  | chunk[5] as u32;
            match id {
                SETTINGS_HEADER_TABLE_SIZE => {
                    self.peer_settings.header_table_size = val as usize;
                    self.hpack.dyn_table.update_max_size(val as usize);
                }
                SETTINGS_INITIAL_WINDOW_SIZE => {
                    if val > 0x7fff_ffff {
                        return H2Event::Error { code: ERR_FLOW_CONTROL_ERROR, msg: "window too large" };
                    }
                    self.peer_settings.initial_window_size = val;
                }
                SETTINGS_MAX_FRAME_SIZE => {
                    if val < 16384 || val > 16777215 {
                        return H2Event::Error { code: ERR_FRAME_SIZE_ERROR, msg: "invalid max frame size" };
                    }
                    self.peer_settings.max_frame_size = val;
                }
                SETTINGS_MAX_CONCURRENT_STREAMS => {
                    self.peer_settings.max_concurrent_streams = val;
                }
                SETTINGS_ENABLE_PUSH => {
                    self.peer_settings.enable_push = val != 0;
                }
                SETTINGS_MAX_HEADER_LIST_SIZE => {
                    self.peer_settings.max_header_list_size = val;
                }
                _ => {} // ignore unknown settings
            }
        }
        H2Event::Settings { ack: false }
    }

    fn handle_headers(&mut self, hdr: &FrameHeader, payload: &[u8]) -> H2Event {
        let sid        = hdr.stream_id;
        let end_stream = hdr.flags & FLAG_END_STREAM  != 0;
        let end_hdrs   = hdr.flags & FLAG_END_HEADERS != 0;

        // Strip padding
        let (fragment, _) = strip_padding(payload, hdr.flags);

        // Strip PRIORITY bytes if present
        let fragment = if hdr.flags & FLAG_PRIORITY != 0 && fragment.len() >= 5 {
            &fragment[5..]
        } else {
            fragment
        };

        let stream = self.streams.entry(sid).or_insert(H2Stream {
            state:           StreamState::Idle,
            window:          self.peer_settings.initial_window_size as i64,
            pending_headers: Vec::new(),
        });
        stream.state = StreamState::Open;
        stream.pending_headers.extend_from_slice(fragment);

        if !end_hdrs {
            self.continuation_sid = sid;
            return H2Event::NeedMore; // wait for CONTINUATION
        }

        let fragment_bytes = match self.streams.get_mut(&sid) {
            Some(s) => std::mem::take(&mut s.pending_headers),
            None => return H2Event::Error { code: ERR_STREAM_CLOSED, msg: "stream vanished before HEADERS complete" },
        };
        match self.hpack.decode(&fragment_bytes) {
            Ok(headers) => {
                if end_stream {
                    if let Some(s) = self.streams.get_mut(&sid) {
                        s.state = StreamState::HalfClosedRemote;
                    }
                }
                H2Event::Headers { stream_id: sid, headers, end_stream }
            }
            Err(e) => {
                eprintln!("[h2] HPACK decode error: {}", e);
                H2Event::Error { code: ERR_COMPRESSION_ERROR, msg: "HPACK decode failed" }
            }
        }
    }

    fn handle_data(&mut self, hdr: &FrameHeader, payload: &[u8]) -> H2Event {
        let sid        = hdr.stream_id;
        let end_stream = hdr.flags & FLAG_END_STREAM != 0;
        let (data, _)  = strip_padding(payload, hdr.flags);

        // Update flow control window
        self.conn_window -= data.len() as i64;
        if let Some(s) = self.streams.get_mut(&sid) {
            s.window -= data.len() as i64;
        }

        if end_stream {
            if let Some(s) = self.streams.get_mut(&sid) {
                s.state = StreamState::Closed;
            }
        }

        H2Event::Data { stream_id: sid, data: data.to_vec(), end_stream }
    }

    fn handle_ping(&mut self, hdr: &FrameHeader, payload: &[u8]) -> H2Event {
        if payload.len() < 8 {
            return H2Event::Error { code: ERR_FRAME_SIZE_ERROR, msg: "PING frame too short" };
        }
        let mut data = [0u8; 8];
        data.copy_from_slice(&payload[..8]);
        H2Event::Ping { data, ack: hdr.flags & FLAG_ACK != 0 }
    }

    fn handle_window_update(&mut self, hdr: &FrameHeader, payload: &[u8]) -> H2Event {
        if payload.len() < 4 {
            return H2Event::Error { code: ERR_FRAME_SIZE_ERROR, msg: "WINDOW_UPDATE too short" };
        }
        let increment = ((payload[0] as u32) << 24 | (payload[1] as u32) << 16
                       | (payload[2] as u32) << 8  | payload[3] as u32) & 0x7fff_ffff;
        if increment == 0 {
            return H2Event::Error { code: ERR_PROTOCOL_ERROR, msg: "WINDOW_UPDATE increment=0" };
        }
        if hdr.stream_id == 0 {
            self.conn_window += increment as i64;
        } else if let Some(s) = self.streams.get_mut(&hdr.stream_id) {
            s.window += increment as i64;
        }
        H2Event::WindowUpdate { stream_id: hdr.stream_id, increment }
    }

    fn handle_rst(&mut self, hdr: &FrameHeader, payload: &[u8]) -> H2Event {
        if payload.len() < 4 {
            return H2Event::Error { code: ERR_FRAME_SIZE_ERROR, msg: "RST_STREAM too short" };
        }
        let error_code = (payload[0] as u32) << 24 | (payload[1] as u32) << 16
                       | (payload[2] as u32) << 8  | payload[3] as u32;
        if let Some(s) = self.streams.get_mut(&hdr.stream_id) {
            s.state = StreamState::Closed;
        }
        H2Event::ResetStream { stream_id: hdr.stream_id, error_code }
    }

    fn handle_goaway(&mut self, payload: &[u8]) -> H2Event {
        if payload.len() < 8 {
            return H2Event::Error { code: ERR_FRAME_SIZE_ERROR, msg: "GOAWAY too short" };
        }
        let last_stream = ((payload[0] as u32) << 24 | (payload[1] as u32) << 16
                         | (payload[2] as u32) << 8  | payload[3] as u32) & 0x7fff_ffff;
        let error_code  = (payload[4] as u32) << 24 | (payload[5] as u32) << 16
                        | (payload[6] as u32) << 8  | payload[7] as u32;
        H2Event::GoAway { last_stream, error_code }
    }

    fn handle_continuation(&mut self, hdr: &FrameHeader, payload: &[u8]) -> H2Event {
        let sid      = hdr.stream_id;
        let end_hdrs = hdr.flags & FLAG_END_HEADERS != 0;

        if sid != self.continuation_sid {
            return H2Event::Error { code: ERR_PROTOCOL_ERROR, msg: "CONTINUATION stream mismatch" };
        }

        if let Some(s) = self.streams.get_mut(&sid) {
            s.pending_headers.extend_from_slice(payload);
        }

        if !end_hdrs {
            return H2Event::NeedMore;
        }

        self.continuation_sid = 0;
        let fragment_bytes = match self.streams.get_mut(&sid) {
            Some(s) => std::mem::take(&mut s.pending_headers),
            None => return H2Event::Error { code: ERR_STREAM_CLOSED, msg: "stream vanished before CONTINUATION complete" },
        };
        match self.hpack.decode(&fragment_bytes) {
            Ok(headers) => H2Event::Headers {
                stream_id: sid,
                headers,
                end_stream: false,
            },
            Err(_) => H2Event::Error { code: ERR_COMPRESSION_ERROR, msg: "HPACK decode failed" },
        }
    }
}

impl Default for H2Conn {
    fn default() -> Self { Self::new() }
}

/// Strip pad length and padding bytes from a HEADERS/DATA payload.
/// Returns `(unpadded_fragment, pad_len)`.
fn strip_padding(payload: &[u8], flags: u8) -> (&[u8], usize) {
    if flags & FLAG_PADDED == 0 || payload.is_empty() {
        return (payload, 0);
    }
    let pad_len = payload[0] as usize;
    let data    = &payload[1..];
    if pad_len >= data.len() {
        return (&[], 0); // malformed
    }
    (&data[..data.len() - pad_len], pad_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings_frame(params: &[(u16, u32)]) -> Vec<u8> {
        let payload_len = params.len() * 6;
        let mut frame = vec![
            (payload_len >> 16) as u8,
            (payload_len >> 8) as u8,
            payload_len as u8,
            FRAME_SETTINGS, 0, 0, 0, 0, 0,
        ];
        for &(id, val) in params {
            frame.push((id >> 8) as u8);
            frame.push(id as u8);
            frame.push((val >> 24) as u8);
            frame.push((val >> 16) as u8);
            frame.push((val >> 8)  as u8);
            frame.push(val         as u8);
        }
        frame
    }

    #[test]
    fn frame_header_parse_roundtrip() {
        let hdr = FrameHeader {
            length:     12,
            frame_type: FRAME_HEADERS,
            flags:      FLAG_END_HEADERS,
            stream_id:  1,
        };
        let bytes   = hdr.serialize();
        let parsed  = FrameHeader::parse(&bytes).unwrap();
        assert_eq!(parsed.length,     12);
        assert_eq!(parsed.frame_type, FRAME_HEADERS);
        assert_eq!(parsed.flags,      FLAG_END_HEADERS);
        assert_eq!(parsed.stream_id,  1);
    }

    #[test]
    fn settings_frame_parsed() {
        let raw   = settings_frame(&[(SETTINGS_MAX_FRAME_SIZE, 32768)]);
        let mut c = H2Conn::new();
        let (ev, consumed) = c.process(&raw);
        assert_eq!(consumed, raw.len());
        assert!(matches!(ev, H2Event::Settings { ack: false }));
        assert_eq!(c.peer_settings.max_frame_size, 32768);
    }

    #[test]
    fn need_more_on_short_buffer() {
        let mut c = H2Conn::new();
        let buf   = &[0u8; 4]; // too short for a frame header
        let (ev, consumed) = c.process(buf);
        assert_eq!(consumed, 0);
        assert!(matches!(ev, H2Event::NeedMore));
    }

    #[test]
    fn settings_ack_frame_correct() {
        let ack = H2Conn::settings_ack_frame();
        let hdr = FrameHeader::parse(&ack).unwrap();
        assert_eq!(hdr.frame_type, FRAME_SETTINGS);
        assert_eq!(hdr.flags, FLAG_ACK);
        assert_eq!(hdr.length, 0);
    }

    #[test]
    fn window_update_frame_correct() {
        let frame = H2Conn::window_update_frame(0, 65535);
        let hdr   = FrameHeader::parse(&frame).unwrap();
        assert_eq!(hdr.frame_type, FRAME_WINDOW_UPDATE);
        assert_eq!(hdr.stream_id, 0);
        let increment = ((frame[9] as u32) << 24 | (frame[10] as u32) << 16
                       | (frame[11] as u32) << 8  | frame[12] as u32) & 0x7fffffff;
        assert_eq!(increment, 65535);
    }
}
