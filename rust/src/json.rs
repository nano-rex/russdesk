//! A small JSON value type, parser and serializer, std-only. Replaces
//! serde_json for this crate. The `json!` macro mirrors serde_json's so call
//! sites read the same.

use std::fmt;
use std::ops::{Index, IndexMut};

/// An insertion-ordered JSON object.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Object {
    entries: Vec<(String, Value)>,
}

impl Object {
    pub fn new() -> Self {
        Object {
            entries: Vec::new(),
        }
    }
    pub fn insert(&mut self, key: String, value: Value) {
        for e in &mut self.entries {
            if e.0 == key {
                e.1 = value;
                return;
            }
        }
        self.entries.push((key, value));
    }
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.entries.iter().find(|e| e.0 == key).map(|e| &e.1)
    }
    pub fn get_mut(&mut self, key: &str) -> Option<&mut Value> {
        self.entries
            .iter_mut()
            .find(|e| e.0 == key)
            .map(|e| &mut e.1)
    }
    pub fn contains_key(&self, key: &str) -> bool {
        self.entries.iter().any(|e| e.0 == key)
    }
    pub fn remove(&mut self, key: &str) -> Option<Value> {
        if let Some(i) = self.entries.iter().position(|e| e.0 == key) {
            Some(self.entries.remove(i).1)
        } else {
            None
        }
    }
    pub fn iter(&self) -> impl Iterator<Item = (&String, &Value)> {
        self.entries.iter().map(|e| (&e.0, &e.1))
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl IntoIterator for Object {
    type Item = (String, Value);
    type IntoIter = std::vec::IntoIter<(String, Value)>;
    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}

impl FromIterator<(String, Value)> for Object {
    fn from_iter<T: IntoIterator<Item = (String, Value)>>(iter: T) -> Self {
        let mut o = Object::new();
        for (k, v) in iter {
            o.insert(k, v);
        }
        o
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Array(Vec<Value>),
    Object(Object),
}

impl Value {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Int(n) => Some(*n),
            _ => None,
        }
    }
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Float(f) => Some(*f),
            Value::Int(n) => Some(*n as f64),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }
    pub fn as_array(&self) -> Option<&Vec<Value>> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }
    pub fn as_object(&self) -> Option<&Object> {
        match self {
            Value::Object(o) => Some(o),
            _ => None,
        }
    }
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_object().and_then(|o| o.get(key))
    }
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }
    pub fn is_boolean(&self) -> bool {
        matches!(self, Value::Bool(_))
    }
}

// -- From conversions ---------------------------------------------------------

// (Value -> Value is covered by std's reflexive `impl From<T> for T`.)
impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Value::Bool(b)
    }
}
impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::Str(s.to_string())
    }
}
impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::Str(s)
    }
}
impl From<&String> for Value {
    fn from(s: &String) -> Self {
        Value::Str(s.clone())
    }
}
impl From<Object> for Value {
    fn from(o: Object) -> Self {
        Value::Object(o)
    }
}
impl From<f64> for Value {
    fn from(f: f64) -> Self {
        Value::Float(f)
    }
}
macro_rules! from_int {
    ($($t:ty),*) => { $( impl From<$t> for Value { fn from(n: $t) -> Self { Value::Int(n as i64) } } )* };
}
from_int!(i8, i16, i32, i64, u8, u16, u32, usize);

impl<T: Into<Value>> From<Option<T>> for Value {
    fn from(o: Option<T>) -> Self {
        match o {
            Some(v) => v.into(),
            None => Value::Null,
        }
    }
}
impl<T: Into<Value>> From<Vec<T>> for Value {
    fn from(v: Vec<T>) -> Self {
        Value::Array(v.into_iter().map(Into::into).collect())
    }
}

// -- indexing (auto-vivifying, like serde_json) -------------------------------

static NULL: Value = Value::Null;

impl Index<&str> for Value {
    type Output = Value;
    fn index(&self, key: &str) -> &Value {
        self.get(key).unwrap_or(&NULL)
    }
}
impl Index<usize> for Value {
    type Output = Value;
    fn index(&self, i: usize) -> &Value {
        self.as_array().and_then(|a| a.get(i)).unwrap_or(&NULL)
    }
}
impl IndexMut<&str> for Value {
    fn index_mut(&mut self, key: &str) -> &mut Value {
        if !matches!(self, Value::Object(_)) {
            *self = Value::Object(Object::new());
        }
        if let Value::Object(o) = self {
            if !o.contains_key(key) {
                o.insert(key.to_string(), Value::Null);
            }
            o.get_mut(key).unwrap()
        } else {
            unreachable!()
        }
    }
}

// -- serialization ------------------------------------------------------------

fn escape_into(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write_value(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Int(n) => out.push_str(&n.to_string()),
        Value::Float(f) => {
            if f.is_finite() {
                out.push_str(&format!("{f}"));
            } else {
                out.push_str("null");
            }
        }
        Value::Str(s) => escape_into(s, out),
        Value::Array(a) => {
            out.push('[');
            for (i, e) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(e, out);
            }
            out.push(']');
        }
        Value::Object(o) => {
            out.push('{');
            for (i, (k, val)) in o.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                escape_into(k, out);
                out.push(':');
                write_value(val, out);
            }
            out.push('}');
        }
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = String::new();
        write_value(self, &mut s);
        f.write_str(&s)
    }
}

pub fn to_string(v: &Value) -> String {
    let mut s = String::new();
    write_value(v, &mut s);
    s
}

// -- parsing ------------------------------------------------------------------

pub fn from_str(input: &str) -> Result<Value, String> {
    let mut p = Parser {
        bytes: input.as_bytes(),
        pos: 0,
    };
    p.skip_ws();
    let v = p.parse_value()?;
    p.skip_ws();
    if p.pos != p.bytes.len() {
        return Err("trailing characters".into());
    }
    Ok(v)
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }
    fn skip_ws(&mut self) {
        while let Some(c) = self.peek() {
            if c == b' ' || c == b'\t' || c == b'\n' || c == b'\r' {
                self.pos += 1;
            } else {
                break;
            }
        }
    }
    fn parse_value(&mut self) -> Result<Value, String> {
        self.skip_ws();
        match self.peek() {
            Some(b'{') => self.parse_object(),
            Some(b'[') => self.parse_array(),
            Some(b'"') => Ok(Value::Str(self.parse_string()?)),
            Some(b't') | Some(b'f') => self.parse_bool(),
            Some(b'n') => self.parse_null(),
            Some(c) if c == b'-' || c.is_ascii_digit() => self.parse_number(),
            _ => Err("unexpected token".into()),
        }
    }
    fn expect(&mut self, c: u8) -> Result<(), String> {
        if self.peek() == Some(c) {
            self.pos += 1;
            Ok(())
        } else {
            Err(format!("expected '{}'", c as char))
        }
    }
    fn parse_object(&mut self) -> Result<Value, String> {
        self.expect(b'{')?;
        let mut o = Object::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Value::Object(o));
        }
        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            self.skip_ws();
            self.expect(b':')?;
            let val = self.parse_value()?;
            o.insert(key, val);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    break;
                }
                _ => return Err("expected ',' or '}'".into()),
            }
        }
        Ok(Value::Object(o))
    }
    fn parse_array(&mut self) -> Result<Value, String> {
        self.expect(b'[')?;
        let mut a = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Value::Array(a));
        }
        loop {
            let val = self.parse_value()?;
            a.push(val);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    break;
                }
                _ => return Err("expected ',' or ']'".into()),
            }
        }
        Ok(Value::Array(a))
    }
    fn parse_string(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut s = String::new();
        loop {
            let c = self.peek().ok_or("unterminated string")?;
            self.pos += 1;
            match c {
                b'"' => break,
                b'\\' => {
                    let e = self.peek().ok_or("bad escape")?;
                    self.pos += 1;
                    match e {
                        b'"' => s.push('"'),
                        b'\\' => s.push('\\'),
                        b'/' => s.push('/'),
                        b'n' => s.push('\n'),
                        b't' => s.push('\t'),
                        b'r' => s.push('\r'),
                        b'b' => s.push('\u{08}'),
                        b'f' => s.push('\u{0c}'),
                        b'u' => {
                            let cp = self.parse_hex4()?;
                            if (0xD800..=0xDBFF).contains(&cp) {
                                // surrogate pair
                                if self.peek() == Some(b'\\') {
                                    self.pos += 1;
                                    if self.peek() == Some(b'u') {
                                        self.pos += 1;
                                        let lo = self.parse_hex4()?;
                                        let c = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                                        s.push(char::from_u32(c).unwrap_or('\u{fffd}'));
                                    } else {
                                        return Err("bad surrogate".into());
                                    }
                                } else {
                                    return Err("bad surrogate".into());
                                }
                            } else {
                                s.push(char::from_u32(cp).unwrap_or('\u{fffd}'));
                            }
                        }
                        _ => return Err("bad escape".into()),
                    }
                }
                _ => {
                    // UTF-8: collect this byte and any continuation bytes.
                    if c < 0x80 {
                        s.push(c as char);
                    } else {
                        let mut buf = vec![c];
                        while let Some(n) = self.peek() {
                            if n & 0xC0 == 0x80 {
                                buf.push(n);
                                self.pos += 1;
                            } else {
                                break;
                            }
                        }
                        s.push_str(std::str::from_utf8(&buf).map_err(|_| "bad utf8")?);
                    }
                }
            }
        }
        Ok(s)
    }
    fn parse_hex4(&mut self) -> Result<u32, String> {
        if self.pos + 4 > self.bytes.len() {
            return Err("bad \\u".into());
        }
        let hex =
            std::str::from_utf8(&self.bytes[self.pos..self.pos + 4]).map_err(|_| "bad \\u")?;
        let v = u32::from_str_radix(hex, 16).map_err(|_| "bad \\u")?;
        self.pos += 4;
        Ok(v)
    }
    fn parse_bool(&mut self) -> Result<Value, String> {
        if self.bytes[self.pos..].starts_with(b"true") {
            self.pos += 4;
            Ok(Value::Bool(true))
        } else if self.bytes[self.pos..].starts_with(b"false") {
            self.pos += 5;
            Ok(Value::Bool(false))
        } else {
            Err("invalid literal".into())
        }
    }
    fn parse_null(&mut self) -> Result<Value, String> {
        if self.bytes[self.pos..].starts_with(b"null") {
            self.pos += 4;
            Ok(Value::Null)
        } else {
            Err("invalid literal".into())
        }
    }
    fn parse_number(&mut self) -> Result<Value, String> {
        let start = self.pos;
        let mut is_float = false;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        while let Some(c) = self.peek() {
            match c {
                b'0'..=b'9' => self.pos += 1,
                b'.' | b'e' | b'E' | b'+' | b'-' => {
                    is_float = true;
                    self.pos += 1;
                }
                _ => break,
            }
        }
        let text = std::str::from_utf8(&self.bytes[start..self.pos]).map_err(|_| "bad number")?;
        if is_float {
            text.parse::<f64>()
                .map(Value::Float)
                .map_err(|_| "bad number".into())
        } else {
            match text.parse::<i64>() {
                Ok(n) => Ok(Value::Int(n)),
                Err(_) => text
                    .parse::<f64>()
                    .map(Value::Float)
                    .map_err(|_| "bad number".into()),
            }
        }
    }
}

/// Build a `Value` with JSON-like syntax (a port of serde_json's `json!`).
/// Brought into crate scope by `#[macro_use] mod json;` in main.rs.
macro_rules! json {
    (null) => { $crate::json::Value::Null };
    (true) => { $crate::json::Value::Bool(true) };
    (false) => { $crate::json::Value::Bool(false) };
    ([]) => { $crate::json::Value::Array(::std::vec::Vec::new()) };
    ([ $($tt:tt)+ ]) => {
        $crate::json::Value::Array(json_array!(@acc [] $($tt)+))
    };
    ({}) => { $crate::json::Value::Object($crate::json::Object::new()) };
    ({ $($tt:tt)+ }) => {{
        let mut object = $crate::json::Object::new();
        json_object!(@acc object () ($($tt)+) ($($tt)+));
        $crate::json::Value::Object(object)
    }};
    ($other:expr) => { $crate::json::Value::from($other) };
}

macro_rules! json_array {
    (@acc [$($elems:expr,)*]) => { ::std::vec![$($elems,)*] };
    (@acc [$($elems:expr),*]) => { ::std::vec![$($elems),*] };
    (@acc [$($elems:expr,)*] null $($rest:tt)*) => {
        json_array!(@acc [$($elems,)* json!(null),] $($rest)*)
    };
    (@acc [$($elems:expr,)*] [$($arr:tt)*] $($rest:tt)*) => {
        json_array!(@acc [$($elems,)* json!([$($arr)*]),] $($rest)*)
    };
    (@acc [$($elems:expr,)*] {$($obj:tt)*} $($rest:tt)*) => {
        json_array!(@acc [$($elems,)* json!({$($obj)*}),] $($rest)*)
    };
    (@acc [$($elems:expr,)*] $next:expr, $($rest:tt)*) => {
        json_array!(@acc [$($elems,)* json!($next),] $($rest)*)
    };
    (@acc [$($elems:expr,)*] $last:expr) => {
        json_array!(@acc [$($elems,)* json!($last)])
    };
    (@acc [$($elems:expr,)*] , $($rest:tt)*) => {
        json_array!(@acc [$($elems,)*] $($rest)*)
    };
}

macro_rules! json_object {
    (@acc $object:ident () () ()) => {};
    // last entry, no trailing comma
    (@acc $object:ident [$($key:tt)+] ($value:expr)) => {
        $object.insert(($($key)+).to_string(), $value);
    };
    // entry with trailing comma
    (@acc $object:ident [$($key:tt)+] ($value:expr) , $($rest:tt)*) => {
        $object.insert(($($key)+).to_string(), $value);
        json_object!(@acc $object () ($($rest)*) ($($rest)*));
    };
    // value is an array
    (@acc $object:ident ($($key:tt)+) (: [$($arr:tt)*] $($rest:tt)*) $copy:tt) => {
        json_object!(@acc $object [$($key)+] (json!([$($arr)*])) $($rest)*);
    };
    // value is an object
    (@acc $object:ident ($($key:tt)+) (: {$($obj:tt)*} $($rest:tt)*) $copy:tt) => {
        json_object!(@acc $object [$($key)+] (json!({$($obj)*})) $($rest)*);
    };
    // value is an expression followed by a comma
    (@acc $object:ident ($($key:tt)+) (: $value:expr , $($rest:tt)*) $copy:tt) => {
        json_object!(@acc $object [$($key)+] (json!($value)) , $($rest)*);
    };
    // last value is an expression, no trailing comma
    (@acc $object:ident ($($key:tt)+) (: $value:expr) $copy:tt) => {
        json_object!(@acc $object [$($key)+] (json!($value)));
    };
    // munch a key token
    (@acc $object:ident ($($key:tt)*) ($tt:tt $($rest:tt)*) $copy:tt) => {
        json_object!(@acc $object ($($key)* $tt) ($($rest)*) ($($rest)*));
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macro_builds_values() {
        let v = json!({
            "a": 1,
            "b": [true, null, "x"],
            "c": { "d": 2 },
            "e": rstr(),
        });
        assert_eq!(v["a"].as_i64(), Some(1));
        assert_eq!(v["b"].as_array().unwrap().len(), 3);
        assert_eq!(v["c"]["d"].as_i64(), Some(2));
        assert_eq!(v["e"].as_str(), Some("fn"));
        assert_eq!(v["missing"], Value::Null);
    }

    fn rstr() -> String {
        "fn".to_string()
    }

    #[test]
    fn round_trip() {
        let src = r#"{"n":-12,"f":1.5,"s":"a\"b\n","arr":[1,2,{"x":true}],"z":null}"#;
        let v = from_str(src).unwrap();
        assert_eq!(v["n"].as_i64(), Some(-12));
        assert_eq!(v["s"].as_str(), Some("a\"b\n"));
        assert_eq!(v["arr"][2]["x"].as_bool(), Some(true));
        // serialize and re-parse to confirm stability
        let out = to_string(&v);
        let v2 = from_str(&out).unwrap();
        assert_eq!(v, v2);
    }

    #[test]
    fn index_mut_autovivifies() {
        let mut v = json!({});
        v["a"] = json!(5);
        v["b"]["c"] = json!("deep");
        assert_eq!(v["a"].as_i64(), Some(5));
        assert_eq!(v["b"]["c"].as_str(), Some("deep"));
    }

    #[test]
    fn unicode_and_escapes() {
        let v = from_str(r#""café 😀""#).unwrap();
        assert_eq!(v.as_str().unwrap(), "café 😀");
        let out = to_string(&Value::from("tab\tnl\n"));
        assert_eq!(out, r#""tab\tnl\n""#);
    }

    #[test]
    fn indexing_arrays() {
        let v = from_str("[10,20,30]").unwrap();
        assert_eq!(v[1].as_i64(), Some(20));
    }
}
