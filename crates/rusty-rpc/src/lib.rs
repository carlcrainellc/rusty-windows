//! Talks to a running Session Router over its local RPC.
//!
//! The router's RPC is OxenMQ on `tcp://127.0.0.1:1190` by default (`[api] bind=` in the
//! router config). A request is the multipart message `[command, reply_tag, json]` and the
//! answer comes back as `["REPLY", reply_tag, json]`, where the JSON is
//! `{"result": ...}` on success or `{"error": "..."}` on failure.
//!
//! Commands live in the `llarp.` category and need admin, which the router grants to
//! loopback connections only.

pub mod zmtp;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fmt;
use std::io::{self, BufReader, BufWriter, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

pub const DEFAULT_ADDR: &str = "127.0.0.1:1190";

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    /// The router answered with `{"error": ...}`.
    Router(String),
    /// The answer wasn't in a shape we understand.
    Protocol(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
                write!(
                    f,
                    "Session Router isn't answering on its RPC port (is it running?)"
                )
            }
            Error::Io(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                write!(f, "Session Router didn't answer in time")
            }
            Error::Io(e) => write!(f, "{e}"),
            Error::Router(m) => write!(f, "router: {m}"),
            Error::Protocol(m) => write!(f, "unexpected answer: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// One exit mapping as reported by `list_exits`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExitEntry {
    pub address: String,
    #[serde(default)]
    pub ranges: Vec<String>,
    #[serde(default)]
    pub session_live: bool,
    #[serde(default)]
    pub exit_capable: bool,
    #[serde(default)]
    pub last_activity: Option<i64>,
}

/// Exit mappings plus whether the router's OS routes for them are in place.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExitList {
    /// `None` when the router build doesn't say.
    #[serde(default)]
    pub routes_up: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routes_reason: Option<String>,
    #[serde(default)]
    pub exits: Vec<ExitEntry>,
}

/// Reply to `map_exit`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MapReply {
    /// `None` when the router build doesn't say.
    #[serde(default)]
    pub routes_up: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routes_reason: Option<String>,
    #[serde(default)]
    pub message: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct MapExit {
    pub address: String,
    pub full_tunnel: bool,
    pub ip_ranges: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub token: String,
}

pub struct Client {
    reader: BufReader<TcpStream>,
    writer: BufWriter<TcpStream>,
    next_tag: u64,
    auth: Option<String>,
}

impl Client {
    pub fn connect(addr: &str, timeout: Duration) -> Result<Self> {
        let addr = addr.strip_prefix("tcp://").unwrap_or(addr);
        let sa: SocketAddr = addr
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| Error::Protocol(format!("can't resolve {addr}")))?;
        let stream = TcpStream::connect_timeout(&sa, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        stream.set_nodelay(true)?;
        let mut s = stream.try_clone()?;
        zmtp::handshake(&mut s, "DEALER")?;
        Ok(Client {
            reader: BufReader::new(stream.try_clone()?),
            writer: BufWriter::new(stream),
            next_tag: 1,
            auth: None,
        })
    }

    /// Some router builds (the Windows packaging) require every request to carry the
    /// `[api] auth=` value from the router's config as an `auth` field.
    pub fn with_auth(mut self, auth: Option<String>) -> Self {
        self.auth = auth.filter(|a| !a.is_empty());
        self
    }

    /// Sends one request and waits for its reply. Returns the `result` value.
    pub fn call(&mut self, command: &str, args: &Value) -> Result<Value> {
        let tag = format!("rusty-{}", self.next_tag);
        self.next_tag += 1;
        let body = match (&self.auth, args) {
            (Some(a), Value::Object(m)) => {
                let mut m = m.clone();
                m.insert("auth".into(), Value::String(a.clone()));
                serde_json::to_vec(&Value::Object(m))
            }
            _ => serde_json::to_vec(args),
        }
        .map_err(|e| Error::Protocol(e.to_string()))?;
        zmtp::write_message(
            &mut self.writer,
            &[command.as_bytes(), tag.as_bytes(), &body],
        )?;
        self.writer.flush()?;
        loop {
            let parts = zmtp::read_message(&mut self.reader)?;
            if parts.len() >= 2 && parts[0] == b"REPLY" && parts[1] == tag.as_bytes() {
                let data = parts.get(2).map(Vec::as_slice).unwrap_or(b"");
                return decode_reply(data);
            }
            if parts.first().map(Vec::as_slice) == Some(b"UNKNOWNCOMMAND") {
                return Err(Error::Router(format!(
                    "this router doesn't know `{command}`"
                )));
            }
            if parts.first().map(Vec::as_slice) == Some(b"FORBIDDEN") {
                return Err(Error::Router(format!(
                    "`{command}` needs admin access; connect over loopback"
                )));
            }
            // Anything else (a stale reply, a log line) isn't ours; keep reading.
        }
    }

    pub fn version(&mut self) -> Result<Value> {
        self.call("llarp.version", &json!({}))
    }

    pub fn list_exits(&mut self) -> Result<ExitList> {
        let v = self.call("llarp.list_exits", &json!({}))?;
        if v.is_null() {
            return Err(Error::Protocol(
                "this router build doesn't report exits (it predates map_exit)".into(),
            ));
        }
        // Earlier map-exit builds answer with just the list of exits.
        if let Value::Array(_) = v {
            let exits = serde_json::from_value(v).map_err(|e| Error::Protocol(e.to_string()))?;
            return Ok(ExitList {
                routes_up: None,
                routes_reason: None,
                exits,
            });
        }
        serde_json::from_value(v).map_err(|e| Error::Protocol(e.to_string()))
    }

    pub fn map_exit(&mut self, req: &MapExit) -> Result<MapReply> {
        let args = serde_json::to_value(req).map_err(|e| Error::Protocol(e.to_string()))?;
        let v = self.call("llarp.map_exit", &args)?;
        // Earlier map-exit builds answer with just a message.
        if let Value::String(message) = v {
            return Ok(MapReply {
                routes_up: None,
                routes_reason: None,
                message,
            });
        }
        serde_json::from_value(v).map_err(|e| Error::Protocol(e.to_string()))
    }

    pub fn unmap_exit(&mut self, address: &str) -> Result<()> {
        self.call("llarp.unmap_exit", &json!({ "address": address }))?;
        Ok(())
    }

    pub fn swap_exits(
        &mut self,
        old: &str,
        new: &str,
        full_tunnel: bool,
        ip_ranges: &[String],
        token: &str,
    ) -> Result<String> {
        let mut args = json!({ "exit_addresses": [old, new], "full_tunnel": full_tunnel, "ip_ranges": ip_ranges });
        if !token.is_empty() {
            args["token"] = json!(token);
        }
        let v = self.call("llarp.swap_exits", &args)?;
        Ok(v.as_str().unwrap_or_default().to_string())
    }

    /// Asks the router to shut down cleanly (it removes its own routes on the way out).
    pub fn halt(&mut self) -> Result<()> {
        self.call("llarp.halt", &json!({}))?;
        Ok(())
    }
}

/// Turns the router's reply body into a result or an error.
pub fn decode_reply(data: &[u8]) -> Result<Value> {
    if data.is_empty() {
        return Ok(Value::Null);
    }
    let v: Value = serde_json::from_slice(data)
        .map_err(|e| Error::Protocol(format!("{e}: {}", String::from_utf8_lossy(data))))?;
    match v {
        Value::Object(mut m) => {
            if let Some(err) = m.remove("error") {
                return Err(Error::Router(
                    err.as_str()
                        .map(str::to_string)
                        .unwrap_or_else(|| err.to_string()),
                ));
            }
            Ok(m.remove("result").unwrap_or(Value::Null))
        }
        // A request the router couldn't parse comes back as a one-element array of text.
        Value::Array(a) if a.len() == 1 && a[0].is_string() => {
            Err(Error::Router(a[0].as_str().unwrap().to_string()))
        }
        Value::Null => Ok(Value::Null),
        other => Err(Error::Protocol(other.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn decodes_results_and_errors() {
        assert_eq!(decode_reply(br#"{"result":"OK"}"#).unwrap(), json!("OK"));
        assert!(
            matches!(decode_reply(br#"{"error":"no mapping for that address"}"#), Err(Error::Router(m)) if m == "no mapping for that address")
        );
        assert!(matches!(
            decode_reply(br#"["Failed to parse request parameters: x"]"#),
            Err(Error::Router(_))
        ));
        assert_eq!(decode_reply(b"null").unwrap(), Value::Null);
        assert_eq!(decode_reply(b"").unwrap(), Value::Null);
    }

    #[test]
    fn parses_list_exits_shape() {
        let v = json!({
            "routes_up": false,
            "routes_reason": "no default gateway",
            "exits": [{"address": "abc.sesh", "ranges": ["0.0.0.0/0"], "session_live": true, "exit_capable": true, "last_activity": 12}]
        });
        let l: ExitList = serde_json::from_value(v).unwrap();
        assert_eq!(l.routes_up, Some(false));
        assert_eq!(l.routes_reason.as_deref(), Some("no default gateway"));
        assert_eq!(l.exits[0].ranges, vec!["0.0.0.0/0"]);
    }

    #[test]
    fn older_list_exits_shape() {
        let addr = fake_router(vec![(
            "llarp.list_exits",
            json!({"result": [{"address": "a.sesh", "ranges": ["0.0.0.0/0"], "session_live": false, "exit_capable": false}]}),
        )]);
        let mut c = Client::connect(&addr, Duration::from_secs(5)).unwrap();
        let l = c.list_exits().unwrap();
        assert_eq!(l.exits[0].address, "a.sesh");
        assert_eq!(l.routes_up, None, "older builds don't say");
    }

    /// A tiny stand-in for the router: speaks the server side of ZMTP and answers like OxenMQ.
    fn fake_router(replies: Vec<(&'static str, Value)>) -> String {
        fake_router_auth(replies, None)
    }

    fn fake_router_auth(
        replies: Vec<(&'static str, Value)>,
        need_auth: Option<&'static str>,
    ) -> String {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut g = [0u8; 64];
            io::Read::read_exact(&mut s, &mut g).unwrap();
            zmtp::check_greeting(&g).unwrap();
            s.write_all(&zmtp::greeting(true)).unwrap();
            let f = zmtp::read_frame(&mut s).unwrap();
            assert!(f.command);
            let (name, props) = zmtp::parse_command(&f.body).unwrap();
            assert_eq!(name, "READY");
            assert_eq!(props[0].1, b"DEALER");
            zmtp::write_frame(
                &mut s,
                &zmtp::ready_body(&[("Socket-Type", b"ROUTER")]),
                false,
                true,
            )
            .unwrap();
            for (expect_cmd, reply) in replies {
                let parts = zmtp::read_message(&mut s).unwrap();
                assert_eq!(parts.len(), 3);
                assert_eq!(String::from_utf8_lossy(&parts[0]), expect_cmd);
                let args: Value = serde_json::from_slice(&parts[2]).unwrap();
                if let Some(a) = need_auth {
                    if args.get("auth").and_then(Value::as_str) != Some(a) {
                        let body = serde_json::to_vec(&json!({"error": "Unauthorized"})).unwrap();
                        zmtp::write_message(&mut s, &[b"REPLY", &parts[1], &body]).unwrap();
                        continue;
                    }
                }
                // A heartbeat and an unrelated message first, to check they're skipped.
                zmtp::write_frame(&mut s, b"\x04PING\x00\x00", false, true).unwrap();
                zmtp::write_message(&mut s, &[b"REPLY", b"someone-else", b"{}"]).unwrap();
                let body = serde_json::to_vec(&reply).unwrap();
                zmtp::write_message(&mut s, &[b"REPLY", &parts[1], &body]).unwrap();
            }
        });
        addr
    }

    #[test]
    fn talks_to_a_fake_router() {
        let addr = fake_router(vec![
            ("llarp.version", json!({"result": {"version": [1, 1, 1]}})),
            (
                "llarp.map_exit",
                json!({"result": {"routes_up": true, "message": "mapped 1 range(s) via x.sesh"}}),
            ),
            (
                "llarp.list_exits",
                json!({"result": {"routes_up": true, "exits": [{"address": "x.sesh", "ranges": ["0.0.0.0/0"]}]}}),
            ),
            (
                "llarp.unmap_exit",
                json!({"error": "no mapping for that address"}),
            ),
        ]);
        let mut c = Client::connect(&format!("tcp://{addr}"), Duration::from_secs(5)).unwrap();
        assert_eq!(c.version().unwrap()["version"], json!([1, 1, 1]));
        let r = c
            .map_exit(&MapExit {
                address: "x.sesh".into(),
                full_tunnel: true,
                ..Default::default()
            })
            .unwrap();
        assert_eq!(r.routes_up, Some(true));
        let l = c.list_exits().unwrap();
        assert_eq!(l.exits[0].address, "x.sesh");
        assert!(matches!(c.unmap_exit("y.sesh"), Err(Error::Router(_))));
    }

    #[test]
    fn sends_auth_when_set() {
        let addr = fake_router_auth(
            vec![
                ("llarp.version", json!({"result": "ok"})),
                (
                    "llarp.map_exit",
                    json!({"result": {"routes_up": false, "message": "m"}}),
                ),
            ],
            Some("s3cret"),
        );
        let mut c = Client::connect(&addr, Duration::from_secs(5))
            .unwrap()
            .with_auth(Some("s3cret".into()));
        assert_eq!(c.version().unwrap(), json!("ok"));
        c.map_exit(&MapExit {
            address: "x.sesh".into(),
            ..Default::default()
        })
        .unwrap();

        let addr = fake_router_auth(
            vec![("llarp.version", json!({"result": "ok"}))],
            Some("s3cret"),
        );
        let mut c = Client::connect(&addr, Duration::from_secs(5)).unwrap();
        assert!(matches!(c.version(), Err(Error::Router(m)) if m == "Unauthorized"));
    }

    #[test]
    fn map_exit_omits_empty_token() {
        let v = serde_json::to_value(MapExit {
            address: "a.sesh".into(),
            ..Default::default()
        })
        .unwrap();
        assert!(v.get("token").is_none());
        assert_eq!(v["full_tunnel"], json!(false));
    }
}
