use std::io::{Error, ErrorKind, Result};

const MAGIC: &[u8] = b"KBAD100\0";

#[derive(Debug)]
pub(super) enum Value {
    Scalar,
    Integer(i128),
    Text(String),
    Array(Vec<Self>),
    Map(Vec<(Self, Self)>),
}

impl Value {
    pub(super) fn get(&self, key: &str) -> Option<&Self> {
        self.map()?
            .iter()
            .find(|(name, _)| name.text() == Some(key))
            .map(|(_, value)| value)
    }

    pub(super) fn text(&self) -> Option<&str> {
        match self {
            Self::Text(text) => Some(text),
            _ => None,
        }
    }

    pub(super) fn integer(&self) -> Option<i128> {
        match self {
            &Self::Integer(value) => Some(value),
            _ => None,
        }
    }

    pub(super) fn map(&self) -> Option<&[(Self, Self)]> {
        match self {
            Self::Map(items) => Some(items),
            _ => None,
        }
    }

    pub(super) fn array(&self) -> Option<&[Self]> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }
}

pub(super) fn parse(bytes: &[u8]) -> Result<Value> {
    let mut reader = Reader {
        remaining: bytes
            .strip_prefix(MAGIC)
            .ok_or_else(|| invalid("missing KBAD100 header"))?,
    };
    let value = reader.value(0)?;
    if !reader.remaining.is_empty() {
        return Err(invalid("trailing KBAD100 data"));
    }
    Ok(value)
}

struct Reader<'a> {
    remaining: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let (prefix, rest) = self
            .remaining
            .split_at_checked(count)
            .ok_or_else(|| invalid("truncated KBAD100 value"))?;
        self.remaining = rest;
        Ok(prefix)
    }

    fn word<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into().unwrap())
    }

    fn text(&mut self, count: usize) -> Result<Value> {
        let size = count
            .checked_mul(2)
            .ok_or_else(|| invalid("KBAD100 string length overflow"))?;
        let units: Vec<_> = self
            .take(size)?
            .chunks_exact(2)
            .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
            .collect();
        let mut text = String::from_utf16(&units).map_err(|_| invalid("invalid KBAD100 UTF-16"))?;
        text.retain(|ch| ch != '\0');
        Ok(Value::Text(text))
    }

    fn array(&mut self, count: usize, depth: usize) -> Result<Value> {
        if count > self.remaining.len() {
            return Err(invalid("KBAD100 array exceeds input bounds"));
        }
        (0..count)
            .map(|_| self.value(depth + 1))
            .collect::<Result<_>>()
            .map(Value::Array)
    }

    fn map(&mut self, count: usize, depth: usize) -> Result<Value> {
        if count > self.remaining.len() / 2 {
            return Err(invalid("KBAD100 map exceeds input bounds"));
        }
        (0..count)
            .map(|_| Ok((self.value(depth + 1)?, self.value(depth + 1)?)))
            .collect::<Result<_>>()
            .map(Value::Map)
    }

    fn value(&mut self, depth: usize) -> Result<Value> {
        if depth > 128 {
            return Err(invalid("KBAD100 nesting is too deep"));
        }
        let [tag] = self.word()?;
        match tag {
            0x00..=0x7f | 0xe0..=0xff => Ok(Value::Integer((tag as i8).into())),
            0x80..=0x8f => self.map((tag & 15).into(), depth),
            0x90..=0x9f => self.array((tag & 15).into(), depth),
            0xa0..=0xbf => self.text((tag & 31).into()),
            0xc0..=0xc3 => Ok(Value::Scalar),
            0xc4 | 0xd9 => {
                let [count] = self.word()?;
                self.text(count.into())
            }
            0xc5 | 0xda => {
                let count = u16::from_le_bytes(self.word()?);
                self.text(count.into())
            }
            0xc6 | 0xdb => {
                let count = u32::from_le_bytes(self.word()?);
                self.text(count as usize)
            }
            0xca => {
                self.take(4)?;
                Ok(Value::Scalar)
            }
            0xcb => {
                self.take(8)?;
                Ok(Value::Scalar)
            }
            0xcc => Ok(Value::Integer(u8::from_le_bytes(self.word()?).into())),
            0xcd => Ok(Value::Integer(u16::from_le_bytes(self.word()?).into())),
            0xce => Ok(Value::Integer(u32::from_le_bytes(self.word()?).into())),
            0xcf => Ok(Value::Integer(u64::from_le_bytes(self.word()?).into())),
            0xd0 => Ok(Value::Integer(i8::from_le_bytes(self.word()?).into())),
            0xd1 => Ok(Value::Integer(i16::from_le_bytes(self.word()?).into())),
            0xd2 => Ok(Value::Integer(i32::from_le_bytes(self.word()?).into())),
            0xd3 => Ok(Value::Integer(i64::from_le_bytes(self.word()?).into())),
            0xdc => {
                let count = u16::from_le_bytes(self.word()?);
                self.array(count.into(), depth)
            }
            0xdd => {
                let count = u32::from_le_bytes(self.word()?);
                self.array(count as usize, depth)
            }
            0xde => {
                let count = u16::from_le_bytes(self.word()?);
                self.map(count.into(), depth)
            }
            0xdf => {
                let count = u32::from_le_bytes(self.word()?);
                self.map(count as usize, depth)
            }
            _ => Err(invalid("unsupported KBAD100 value type")),
        }
    }
}

fn invalid(message: &'static str) -> Error {
    Error::new(ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kbad_reads_utf16_keys_and_layer_ids() {
        let bytes = b"KBAD100\0\x81\xa1\x00\x5c\x92\xcc\xff\xcd\x34\x12";
        let object = parse(bytes).unwrap();
        let items = object.get("尀").unwrap().array().unwrap();
        assert_eq!(items[0].integer(), Some(255));
        assert_eq!(items[1].integer(), Some(0x1234));
        assert!(parse(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn kbad_rejects_unbounded_collections_and_trailing_data() {
        assert!(parse(b"KBAD100\0\xdd\xff\xff\xff\xff").is_err());
        assert!(parse(b"KBAD100\0\x80\0").is_err());
    }
}
