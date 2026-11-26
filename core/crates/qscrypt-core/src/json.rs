//! Minimal JSON writer for results handed to the apps, and a small parser
//! for the arguments they send (no serde needed).

pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[derive(Default)]
pub struct Obj {
    s: String,
}

impl Obj {
    pub fn new() -> Obj {
        Obj { s: String::from("{") }
    }

    fn key(&mut self, k: &str) {
        if self.s.len() > 1 {
            self.s.push(',');
        }
        self.s.push_str(&escape(k));
        self.s.push(':');
    }

    pub fn str(mut self, k: &str, v: &str) -> Obj {
        self.key(k);
        self.s.push_str(&escape(v));
        self
    }

    pub fn int(mut self, k: &str, v: i64) -> Obj {
        self.key(k);
        self.s.push_str(&v.to_string());
        self
    }

    pub fn uint(mut self, k: &str, v: u64) -> Obj {
        self.key(k);
        self.s.push_str(&v.to_string());
        self
    }

    pub fn bool(mut self, k: &str, v: bool) -> Obj {
        self.key(k);
        self.s.push_str(if v { "true" } else { "false" });
        self
    }

    /// Inserts already-serialized JSON.
    pub fn raw(mut self, k: &str, json: &str) -> Obj {
        self.key(k);
        self.s.push_str(json);
        self
    }

    pub fn end(mut self) -> String {
        self.s.push('}');
        self.s
    }
}

pub fn array<I: IntoIterator<Item = String>>(items: I) -> String {
    let mut s = String::from("[");
    for (i, item) in items.into_iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&item);
    }
    s.push(']');
    s
}

// ---------------------------------------------------------------- parsing

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Value>),
    Obj(Vec<(String, Value)>),
}

static NULL: Value = Value::Null;

impl Value {
    pub fn get(&self, key: &str) -> &Value {
        match self {
            Value::Obj(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v).unwrap_or(&NULL),
            _ => &NULL,
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn str_or<'a>(&'a self, d: &'a str) -> &'a str {
        self.as_str().unwrap_or(d)
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Num(n) if n.fract() == 0.0 && n.abs() < 9.0e15 => Some(*n as i64),
            Value::Str(s) => s.parse().ok(),
            _ => None,
        }
    }

    pub fn i64_or(&self, d: i64) -> i64 {
        self.as_i64().unwrap_or(d)
    }

    pub fn u64_or(&self, d: u64) -> u64 {
        self.as_i64().filter(|v| *v >= 0).map(|v| v as u64).unwrap_or(d)
    }

    pub fn bool_or(&self, d: bool) -> bool {
        match self {
            Value::Bool(b) => *b,
            _ => d,
        }
    }

    pub fn as_arr(&self) -> &[Value] {
        match self {
            Value::Arr(a) => a,
            _ => &[],
        }
    }
}

pub fn parse(text: &str) -> Result<Value, String> {
    let b = text.as_bytes();
    let mut p = Parser { b, i: 0, depth: 0 };
    let v = p.value()?;
    p.ws();
    if p.i != b.len() {
        return Err("trailing characters".into());
    }
    Ok(v)
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
    depth: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\n' | b'\r' | b'\t') {
            self.i += 1;
        }
    }

    fn eat(&mut self, c: u8) -> Result<(), String> {
        self.ws();
        if self.b.get(self.i) == Some(&c) {
            self.i += 1;
            Ok(())
        } else {
            Err(format!("expected '{}' at {}", c as char, self.i))
        }
    }

    fn value(&mut self) -> Result<Value, String> {
        self.ws();
        self.depth += 1;
        if self.depth > 64 {
            return Err("nested too deeply".into());
        }
        let v = match self.b.get(self.i) {
            Some(b'{') => {
                self.i += 1;
                let mut m = Vec::new();
                self.ws();
                if self.b.get(self.i) == Some(&b'}') {
                    self.i += 1;
                } else {
                    loop {
                        self.ws();
                        let k = self.string()?;
                        self.eat(b':')?;
                        m.push((k, self.value()?));
                        self.ws();
                        match self.b.get(self.i) {
                            Some(b',') => self.i += 1,
                            Some(b'}') => {
                                self.i += 1;
                                break;
                            }
                            _ => return Err("expected , or }".into()),
                        }
                    }
                }
                Value::Obj(m)
            }
            Some(b'[') => {
                self.i += 1;
                let mut a = Vec::new();
                self.ws();
                if self.b.get(self.i) == Some(&b']') {
                    self.i += 1;
                } else {
                    loop {
                        a.push(self.value()?);
                        self.ws();
                        match self.b.get(self.i) {
                            Some(b',') => self.i += 1,
                            Some(b']') => {
                                self.i += 1;
                                break;
                            }
                            _ => return Err("expected , or ]".into()),
                        }
                    }
                }
                Value::Arr(a)
            }
            Some(b'"') => Value::Str(self.string()?),
            Some(b't') if self.b[self.i..].starts_with(b"true") => {
                self.i += 4;
                Value::Bool(true)
            }
            Some(b'f') if self.b[self.i..].starts_with(b"false") => {
                self.i += 5;
                Value::Bool(false)
            }
            Some(b'n') if self.b[self.i..].starts_with(b"null") => {
                self.i += 4;
                Value::Null
            }
            Some(c) if *c == b'-' || c.is_ascii_digit() => {
                let s = self.i;
                while self.i < self.b.len() && matches!(self.b[self.i], b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9') {
                    self.i += 1;
                }
                let t = std::str::from_utf8(&self.b[s..self.i]).map_err(|e| e.to_string())?;
                Value::Num(t.parse().map_err(|_| format!("bad number {t}"))?)
            }
            _ => return Err(format!("unexpected input at {}", self.i)),
        };
        self.depth -= 1;
        Ok(v)
    }

    fn string(&mut self) -> Result<String, String> {
        if self.b.get(self.i) != Some(&b'"') {
            return Err("expected string".into());
        }
        self.i += 1;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let c = *self.b.get(self.i).ok_or("unterminated string")?;
            self.i += 1;
            match c {
                b'"' => break,
                b'\\' => {
                    let e = *self.b.get(self.i).ok_or("bad escape")?;
                    self.i += 1;
                    match e {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'b' => out.push(8),
                        b'f' => out.push(12),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let hex = |p: &mut Self| -> Result<u32, String> {
                                let h = p.b.get(p.i..p.i + 4).ok_or("bad \\u escape")?;
                                p.i += 4;
                                u32::from_str_radix(std::str::from_utf8(h).map_err(|e| e.to_string())?, 16).map_err(|e| e.to_string())
                            };
                            let mut cp = hex(self)?;
                            if (0xD800..0xDC00).contains(&cp) && self.b.get(self.i..self.i + 2) == Some(b"\\u") {
                                self.i += 2;
                                let lo = hex(self)?;
                                cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                            }
                            let ch = char::from_u32(cp).unwrap_or('\u{FFFD}');
                            let mut buf = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        _ => return Err("bad escape".into()),
                    }
                }
                c => out.push(c),
            }
        }
        String::from_utf8(out).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses() {
        let v = super::parse(r#" {"a": 1, "b": [true, null, "x\u0627\"y"], "c": {"d": -2.5e1}} "#).unwrap();
        assert_eq!(v.get("a").i64_or(0), 1);
        assert_eq!(v.get("b").as_arr()[2].as_str(), Some("x\u{0627}\"y"));
        assert_eq!(v.get("c").get("d"), &super::Value::Num(-25.0));
        assert!(v.get("missing").is_null());
        assert!(super::parse("{\"a\":}").is_err());
        assert!(super::parse("[1,2").is_err());
    }

    use super::*;

    #[test]
    fn builds_objects() {
        let j = Obj::new().str("name", "a\"b\\c\n").int("n", -3).bool("ok", true).raw("list", &array(vec!["1".into(), "2".into()])).end();
        assert_eq!(j, r#"{"name":"a\"b\\c\n","n":-3,"ok":true,"list":[1,2]}"#);
        assert_eq!(escape("خزنة"), "\"خزنة\"");
    }
}
