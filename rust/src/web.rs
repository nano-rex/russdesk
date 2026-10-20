//! A minimal request/response layer and threaded HTTP/1.1 server over std.
//! Port of web.py (which built the same thing on Python's http.server).

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use crate::json::{Object, Value};

pub const MAX_BODY: usize = 2 * 1024 * 1024;

pub type Params = HashMap<String, String>;

/// An error carrying an HTTP status, mirroring web.py's HTTPError.
#[derive(Debug)]
pub struct HttpError {
    pub status: u16,
    pub message: String,
}

impl HttpError {
    pub fn new(status: u16, message: impl Into<String>) -> Self {
        HttpError {
            status,
            message: message.into(),
        }
    }
}

pub type HttpResult<T> = Result<T, HttpError>;

pub struct Request {
    pub method: String,
    pub path: String,
    pub query: HashMap<String, String>,
    pub headers: HashMap<String, String>, // lower-cased keys
    pub body: Vec<u8>,
    pub ip: String,
    pub scheme: String,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(&name.to_lowercase()).map(|s| s.as_str())
    }

    /// Parse the body as JSON whatever the Content-Type (the client posts JSON
    /// as text/plain).
    pub fn json(&self) -> HttpResult<Value> {
        if self.body.is_empty() {
            return Ok(Value::Null);
        }
        let text =
            std::str::from_utf8(&self.body).map_err(|_| HttpError::new(400, "Invalid JSON body"))?;
        crate::json::from_str(text).map_err(|_| HttpError::new(400, "Invalid JSON body"))
    }

    pub fn json_object(&self) -> HttpResult<Object> {
        match self.json()? {
            Value::Object(m) => Ok(m),
            Value::Null => Ok(Object::new()),
            _ => Err(HttpError::new(400, "Expected a JSON object")),
        }
    }

    pub fn cookie(&self, name: &str) -> Option<String> {
        let raw = self.header("cookie")?;
        for part in raw.split(';') {
            let part = part.trim();
            if let Some((k, v)) = part.split_once('=') {
                if k == name {
                    return Some(v.to_string());
                }
            }
        }
        None
    }

    pub fn bearer(&self) -> Option<String> {
        let auth = self.header("authorization")?;
        if auth.len() >= 7 && auth[..7].eq_ignore_ascii_case("bearer ") {
            Some(auth[7..].trim().to_string())
        } else {
            None
        }
    }
}

pub struct Response {
    pub body: Vec<u8>,
    pub status: u16,
    pub content_type: String,
    pub headers: Vec<(String, String)>,
}

impl Response {
    pub fn new(body: Vec<u8>, status: u16, content_type: &str) -> Self {
        Response {
            body,
            status,
            content_type: content_type.to_string(),
            headers: Vec::new(),
        }
    }

    pub fn with_header(mut self, k: &str, v: &str) -> Self {
        self.headers.push((k.to_string(), v.to_string()));
        self
    }
}

pub fn json_response(value: &Value, status: u16) -> Response {
    Response::new(crate::json::to_string(value).into_bytes(), status, "application/json")
}

pub fn error_response(status: u16, message: &str) -> Response {
    json_response(&json!({ "error": message }), status)
}

impl From<HttpError> for Response {
    fn from(e: HttpError) -> Self {
        error_response(e.status, &e.message)
    }
}

// -- router -------------------------------------------------------------------

pub type Handler<A> = dyn Fn(&A, &Request, &Params) -> HttpResult<Response> + Send + Sync;

pub enum Match<'a, A> {
    Found(&'a Handler<A>, Params),
    MethodNotAllowed,
    NotFound,
}

struct Route<A> {
    method: String,
    segments: Vec<Seg>,
    handler: Box<Handler<A>>,
}

enum Seg {
    Literal(String),
    Param(String),
}

fn parse_pattern(pattern: &str) -> Vec<Seg> {
    pattern
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|s| {
            if s.starts_with('<') && s.ends_with('>') {
                Seg::Param(s[1..s.len() - 1].to_string())
            } else {
                Seg::Literal(s.to_string())
            }
        })
        .collect()
}

pub struct Router<A> {
    routes: Vec<Route<A>>,
}

impl<A> Default for Router<A> {
    fn default() -> Self {
        Router { routes: Vec::new() }
    }
}

impl<A> Router<A> {
    pub fn new() -> Self {
        Router::default()
    }

    pub fn add(
        &mut self,
        method: &str,
        pattern: &str,
        handler: impl Fn(&A, &Request, &Params) -> HttpResult<Response> + Send + Sync + 'static,
    ) {
        self.routes.push(Route {
            method: method.to_string(),
            segments: parse_pattern(pattern),
            handler: Box::new(handler),
        });
    }

    /// (handler, params) for a route, or whether the path exists with another
    /// method (405) or not at all (404).
    pub fn match_route(&self, method: &str, path: &str) -> Match<'_, A> {
        let path_segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let mut known = false;
        for route in &self.routes {
            if route.segments.len() != path_segs.len() {
                continue;
            }
            let mut params = Params::new();
            let mut ok = true;
            for (seg, part) in route.segments.iter().zip(&path_segs) {
                match seg {
                    Seg::Literal(l) => {
                        if l != part {
                            ok = false;
                            break;
                        }
                    }
                    Seg::Param(name) => {
                        params.insert(name.clone(), urldecode(part));
                    }
                }
            }
            if ok {
                if route.method == method {
                    return Match::Found(route.handler.as_ref(), params);
                }
                known = true;
            }
        }
        if known {
            Match::MethodNotAllowed
        } else {
            Match::NotFound
        }
    }
}

// -- url helpers --------------------------------------------------------------

pub fn urldecode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(v);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn parse_query(raw: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for pair in raw.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        map.insert(urldecode(k), urldecode(v));
    }
    map
}

// -- server -------------------------------------------------------------------

pub struct ServerConfig {
    pub trust_proxy: bool,
    /// Per-path body limit; returns the maximum allowed body for a path.
    pub body_limit: fn(&str) -> usize,
    pub common_headers: Vec<(String, String)>,
}

/// Start the HTTP server. `handler` turns a parsed Request into a Response.
/// Blocks forever (one thread per connection). Returns the bound address.
pub fn serve<F>(addr: &str, server_cfg: ServerConfig, handler: F) -> std::io::Result<()>
where
    F: Fn(Request) -> Response + Send + Sync + 'static,
{
    let listener = TcpListener::bind(addr)?;
    let local = listener.local_addr()?;
    eprintln!("RussDesk listening on http://{local}");
    let handler = Arc::new(handler);
    let cfg = Arc::new(server_cfg);
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        let handler = handler.clone();
        let cfg = cfg.clone();
        std::thread::spawn(move || {
            let _ = handle_connection(stream, handler.as_ref(), &cfg);
        });
    }
    Ok(())
}

fn handle_connection<F>(stream: TcpStream, handler: &F, cfg: &ServerConfig) -> std::io::Result<()>
where
    F: Fn(Request) -> Response,
{
    let peer_ip = stream
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_default();
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;

    loop {
        // Request line.
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            return Ok(()); // connection closed
        }
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        let mut it = line.split_whitespace();
        let (method, target) = match (it.next(), it.next()) {
            (Some(m), Some(t)) => (m.to_string(), t.to_string()),
            _ => {
                write_response(&mut writer, &error_response(400, "Bad request"), false, cfg)?;
                return Ok(());
            }
        };

        // Headers.
        let mut headers: HashMap<String, String> = HashMap::new();
        loop {
            let mut h = String::new();
            if reader.read_line(&mut h)? == 0 {
                return Ok(());
            }
            let h = h.trim_end();
            if h.is_empty() {
                break;
            }
            if let Some((k, v)) = h.split_once(':') {
                headers.insert(k.trim().to_lowercase(), v.trim().to_string());
            }
        }

        // Body.
        let length: usize = headers
            .get("content-length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let limit = (cfg.body_limit)(target.split('?').next().unwrap_or(""));
        if length > limit {
            write_response(
                &mut writer,
                &error_response(413, "Request body too large"),
                false,
                cfg,
            )?;
            return Ok(());
        }
        let mut body = vec![0u8; length];
        if length > 0 {
            reader.read_exact(&mut body)?;
        }

        let (path, query_raw) = match target.split_once('?') {
            Some((p, q)) => (p.to_string(), q.to_string()),
            None => (target.clone(), String::new()),
        };

        let ip = client_ip(&peer_ip, &headers, cfg.trust_proxy);
        let scheme = if cfg.trust_proxy {
            headers
                .get("x-forwarded-proto")
                .map(|v| v.split(',').next().unwrap_or("http").trim().to_string())
                .unwrap_or_else(|| "http".to_string())
        } else {
            "http".to_string()
        };

        let keep_alive = headers
            .get("connection")
            .map(|v| !v.eq_ignore_ascii_case("close"))
            .unwrap_or(true);
        let is_head = method == "HEAD";

        let req = Request {
            method,
            path,
            query: parse_query(&query_raw),
            headers,
            body,
            ip,
            scheme,
        };

        let resp = handler(req);
        write_response(&mut writer, &resp, is_head, cfg)?;

        if !keep_alive {
            return Ok(());
        }
    }
}

fn client_ip(peer: &str, headers: &HashMap<String, String>, trust_proxy: bool) -> String {
    let mut ip = peer.to_string();
    if trust_proxy {
        if let Some(fwd) = headers.get("x-forwarded-for") {
            if let Some(first) = fwd.split(',').next() {
                ip = first.trim().to_string();
            }
        } else if let Some(real) = headers.get("x-real-ip") {
            ip = real.clone();
        }
    }
    if let Some(stripped) = ip.strip_prefix("::ffff:") {
        ip = stripped.to_string();
    }
    ip
}

fn write_response(
    writer: &mut TcpStream,
    resp: &Response,
    head_only: bool,
    cfg: &ServerConfig,
) -> std::io::Result<()> {
    let reason = reason_phrase(resp.status);
    let mut out = format!("HTTP/1.1 {} {}\r\n", resp.status, reason);
    out.push_str(&format!("Content-Type: {}\r\n", resp.content_type));
    out.push_str(&format!("Content-Length: {}\r\n", resp.body.len()));
    for (k, v) in &cfg.common_headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    for (k, v) in &resp.headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str("\r\n");
    writer.write_all(out.as_bytes())?;
    if !head_only {
        writer.write_all(&resp.body)?;
    }
    writer.flush()
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "OK",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyApp;

    #[test]
    fn router_matches_and_captures() {
        let mut r: Router<DummyApp> = Router::new();
        r.add("GET", "/api/users/<id>", |_a, _req, p| {
            Ok(json_response(&json!({ "id": p.get("id") }), 200))
        });
        match r.match_route("GET", "/api/users/42") {
            Match::Found(_, params) => assert_eq!(params.get("id").unwrap(), "42"),
            _ => panic!("expected match"),
        }
        assert!(matches!(
            r.match_route("POST", "/api/users/42"),
            Match::MethodNotAllowed
        ));
        assert!(matches!(
            r.match_route("GET", "/api/nope"),
            Match::NotFound
        ));
    }

    #[test]
    fn urldecode_works() {
        assert_eq!(urldecode("a%20b+c"), "a b c");
        assert_eq!(urldecode("plain"), "plain");
    }

    #[test]
    fn query_parsing() {
        let q = parse_query("a=1&b=two%20words&c");
        assert_eq!(q.get("a").unwrap(), "1");
        assert_eq!(q.get("b").unwrap(), "two words");
        assert_eq!(q.get("c").unwrap(), "");
    }
}
