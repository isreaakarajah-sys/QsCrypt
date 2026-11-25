//! Minimal JSON writer for results handed to the apps (no serde needed).

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_objects() {
        let j = Obj::new().str("name", "a\"b\\c\n").int("n", -3).bool("ok", true).raw("list", &array(vec!["1".into(), "2".into()])).end();
        assert_eq!(j, r#"{"name":"a\"b\\c\n","n":-3,"ok":true,"list":[1,2]}"#);
        assert_eq!(escape("خزنة"), "\"خزنة\"");
    }
}
