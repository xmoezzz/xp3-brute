use std::io::Result;

use super::{invalid, kbad::Value};

pub(super) fn parse(bytes: &[u8]) -> Result<Value> {
    let bytes = bytes
        .strip_prefix(&[0xff, 0xfe])
        .filter(|bytes| bytes.len().is_multiple_of(2))
        .ok_or_else(|| invalid("expected UTF-16LE TJS const data"))?;
    let units: Vec<_> = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    let text = String::from_utf16(&units).map_err(|_| invalid("invalid TJS const UTF-16"))?;
    let mut reader = Reader { rest: &text };
    if !text.trim_start().starts_with("(const)") {
        return Err(invalid("expected a serialized (const) expression"));
    }
    let value = reader.value(0)?;
    if !reader.rest.trim().is_empty() {
        return Err(invalid("trailing TJS const data"));
    }
    Ok(value)
}

struct Reader<'a> {
    rest: &'a str,
}

impl Reader<'_> {
    fn take(&mut self, prefix: &str) -> bool {
        self.rest = self.rest.trim_start();
        let Some(rest) = self.rest.strip_prefix(prefix) else {
            return false;
        };
        self.rest = rest;
        true
    }

    fn sequence<T>(&mut self, mut item: impl FnMut(&mut Self) -> Result<T>) -> Result<Vec<T>> {
        let mut items = Vec::new();
        while !self.take("]") {
            items.push(item(self)?);
            if !self.take(",") {
                if !self.take("]") {
                    return Err(invalid("expected ',' or ']' in TJS const data"));
                }
                break;
            }
        }
        Ok(items)
    }

    fn value(&mut self, depth: usize) -> Result<Value> {
        if depth > 128 {
            return Err(invalid("TJS const nesting is too deep"));
        }
        let is_const = self.take("(const)");
        if self.take("%[") {
            return self
                .sequence(|reader| {
                    let key = reader.value(depth + 1)?;
                    if !reader.take("=>") {
                        return Err(invalid("expected '=>' in TJS const dictionary"));
                    }
                    Ok((key, reader.value(depth + 1)?))
                })
                .map(Value::Map);
        }
        if self.take("[") {
            return self
                .sequence(|reader| reader.value(depth + 1))
                .map(Value::Array);
        }
        if is_const {
            return Err(invalid("expected a TJS const dictionary or array"));
        }
        if self.take("void") {
            return Ok(Value::Scalar);
        }
        if self.rest.starts_with('"') {
            return self.string();
        }

        let number = self.rest.strip_prefix('-').unwrap_or(self.rest);
        let digits = number.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return Err(invalid("invalid TJS const value"));
        }
        let end = digits + self.rest.len() - number.len();
        let (text, rest) = self.rest.split_at(end);
        self.rest = rest;
        text.parse()
            .map(Value::Integer)
            .map_err(|_| invalid("invalid TJS const integer"))
    }

    fn string(&mut self) -> Result<Value> {
        let mut escaped = false;
        for (i, byte) in self.rest.bytes().enumerate().skip(1) {
            match (escaped, byte) {
                (false, b'"') => {
                    let (text, rest) = self.rest.split_at(i + 1);
                    self.rest = rest;
                    // The serialized strings in these constants use JSON-compatible escapes.
                    return serde_json::from_str(text)
                        .map(Value::Text)
                        .map_err(|_| invalid("invalid TJS const string"));
                }
                _ => escaped = !escaped && byte == b'\\',
            }
        }
        Err(invalid("unterminated TJS const string"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16(text: &str) -> Vec<u8> {
        [0xff, 0xfe]
            .into_iter()
            .chain(text.encode_utf16().flat_map(u16::to_le_bytes))
            .collect()
    }

    #[test]
    fn reads_nested_constants_and_escaped_strings() {
        let value = parse(&utf16(
            r#"(const) %[ "大" => (const) ["command(\"条件\")", -9223372036854775808, void] ]"#,
        ))
        .unwrap();
        let values = value.get("大").unwrap().array().unwrap();
        assert_eq!(values[0].text(), Some("command(\"条件\")"));
        assert_eq!(values[1].integer(), Some(i64::MIN as i128));
        assert!(matches!(values[2], Value::Scalar));
    }

    #[test]
    fn rejects_code_truncation_and_excessive_nesting() {
        for text in ["(const) [] + run()", "(const) %[\"x\" =>", "(const) [1 2]"] {
            assert!(parse(&utf16(text)).is_err(), "{text}");
        }
        let text = format!("(const) {}1{}", "[".repeat(130), "]".repeat(130));
        assert!(parse(&utf16(&text)).is_err());
    }
}
