//! Structured filename/reference mining for recovered Kirikiri scripts.
//!
//! HXV4 stores hashes rather than plaintext filenames.  Name recovery therefore
//! needs high-recall candidate generation followed by exact native-hash matching.
//! This module deliberately parses scripts instead of treating them as bags of
//! printable strings:
//!
//! * compiled TJS2 bytecode is loaded/decompiled by `tjs2dec`, then lexed and
//!   parsed here so string literals keep their call/assignment context;
//! * source TJS uses the same lexer/parser directly;
//! * KAG/KS is parsed by a small quote-aware tag lexer/parser, including embedded
//!   `[iscript] ... [endscript]` TJS blocks.
//!
//! False candidates are safe at the HXV4 layer because a recovered name is only
//! accepted after its path/name hash exactly matches the authenticated Special
//! index.

use std::collections::HashSet;

use encoding_rs::SHIFT_JIS;
use tjs2dec::decompile::srcgen_high::dump_src_file as dump_tjs_source_high;
use tjs2dec::{emit_executable_tjs, load_tjs2_bytecode};

use crate::validate::decode_kirikiri_text;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScriptKind {
    TjsBytecode,
    TjsSource,
    Kag,
}

impl ScriptKind {
    pub fn label(&self) -> &'static str {
        match self {
            Self::TjsBytecode => "tjs-bytecode",
            Self::TjsSource => "tjs-source",
            Self::Kag => "ks-kag",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScriptReference {
    pub line: usize,
    pub context: String,
    pub value: String,
}

#[derive(Clone, Debug)]
pub struct ScriptMiningReport {
    pub kind: ScriptKind,
    pub references: Vec<ScriptReference>,
    pub candidates: HashSet<String>,
    /// High-level TJS emitted by tjs2dec when the input was compiled bytecode.
    pub decompiled_tjs: Option<String>,
    /// Low-level executable TJS is kept as a second source when high-level
    /// decompilation fails or omits a constant/call context.
    pub executable_tjs: Option<String>,
    pub notes: Vec<String>,
}

pub fn analyze_script_names(name: &str, bytes: &[u8]) -> Option<ScriptMiningReport> {
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".tjs") {
        return Some(analyze_tjs(bytes));
    }
    if lower.ends_with(".ks") || lower.ends_with(".kag") {
        return Some(analyze_kag(bytes));
    }
    None
}

fn analyze_tjs(bytes: &[u8]) -> ScriptMiningReport {
    if bytes.starts_with(b"TJS2100\0") {
        let mut notes = Vec::new();
        match load_tjs2_bytecode(bytes) {
            Ok(file) => {
                let high = match dump_tjs_source_high(&file) {
                    Ok(text) => Some(text),
                    Err(err) => {
                        notes.push(format!("tjs2dec high-level decompile failed: {err}"));
                        None
                    }
                };
                let executable = match emit_executable_tjs(&file) {
                    Ok(text) => Some(text),
                    Err(err) => {
                        notes.push(format!("tjs2dec executable-TJS emission failed: {err}"));
                        None
                    }
                };
                let mut references = Vec::new();
                if let Some(text) = high.as_deref() {
                    references.extend(parse_tjs_references(text));
                }
                if let Some(text) = executable.as_deref() {
                    merge_unique_refs(&mut references, parse_tjs_references(text));
                }
                let candidates = references_to_candidates(&references);
                return ScriptMiningReport {
                    kind: ScriptKind::TjsBytecode,
                    references,
                    candidates,
                    decompiled_tjs: high,
                    executable_tjs: executable,
                    notes,
                };
            }
            Err(err) => {
                notes.push(format!("tjs2dec bytecode load failed: {err}"));
                return ScriptMiningReport {
                    kind: ScriptKind::TjsBytecode,
                    references: Vec::new(),
                    candidates: HashSet::new(),
                    decompiled_tjs: None,
                    executable_tjs: None,
                    notes,
                };
            }
        }
    }

    let text = decode_script_text(bytes);
    let references = parse_tjs_references(&text);
    let candidates = references_to_candidates(&references);
    ScriptMiningReport {
        kind: ScriptKind::TjsSource,
        references,
        candidates,
        decompiled_tjs: None,
        executable_tjs: None,
        notes: Vec::new(),
    }
}

fn analyze_kag(bytes: &[u8]) -> ScriptMiningReport {
    let text = decode_script_text(bytes);
    let mut parser = KagParser::new(&text);
    let mut references = parser.parse();
    for block in parser.embedded_tjs {
        merge_unique_refs(&mut references, parse_tjs_references(&block.text));
    }
    let candidates = references_to_candidates(&references);
    ScriptMiningReport {
        kind: ScriptKind::Kag,
        references,
        candidates,
        decompiled_tjs: None,
        executable_tjs: None,
        notes: parser.notes,
    }
}

fn merge_unique_refs(dst: &mut Vec<ScriptReference>, src: Vec<ScriptReference>) {
    let mut seen: HashSet<(usize, String, String)> = dst
        .iter()
        .map(|r| (r.line, r.context.clone(), r.value.clone()))
        .collect();
    for r in src {
        let key = (r.line, r.context.clone(), r.value.clone());
        if seen.insert(key) {
            dst.push(r);
        }
    }
}

fn decode_script_text(bytes: &[u8]) -> String {
    let decoded_storage = decode_kirikiri_text(bytes);
    let bytes = decoded_storage.as_deref().unwrap_or(bytes);
    if bytes.starts_with(&[0xff, 0xfe]) {
        let words: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|p| u16::from_le_bytes([p[0], p[1]]))
            .collect();
        return String::from_utf16_lossy(&words);
    }
    if bytes.starts_with(&[0xfe, 0xff]) {
        let words: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|p| u16::from_be_bytes([p[0], p[1]]))
            .collect();
        return String::from_utf16_lossy(&words);
    }
    if let Ok(text) = std::str::from_utf8(bytes) {
        return text.trim_start_matches('\u{feff}').to_string();
    }
    let (sjis, _, _) = SHIFT_JIS.decode(bytes);
    sjis.into_owned()
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum TjsTokenKind {
    Ident(String),
    String(String),
    Number(String),
    Symbol(char),
    Operator(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TjsToken {
    kind: TjsTokenKind,
    line: usize,
}

struct TjsLexer<'a> {
    chars: Vec<char>,
    pos: usize,
    line: usize,
    _src: &'a str,
}

impl<'a> TjsLexer<'a> {
    fn new(src: &'a str) -> Self {
        Self {
            chars: src.chars().collect(),
            pos: 0,
            line: 1,
            _src: src,
        }
    }

    fn lex(mut self) -> Vec<TjsToken> {
        let mut out = Vec::new();
        while self.pos < self.chars.len() {
            let c = self.chars[self.pos];
            if c == '\n' {
                self.line += 1;
                self.pos += 1;
                continue;
            }
            if c.is_whitespace() {
                self.pos += 1;
                continue;
            }

            if c == '/' && self.peek(1) == Some('/') {
                self.pos += 2;
                while self.pos < self.chars.len() && self.chars[self.pos] != '\n' {
                    self.pos += 1;
                }
                continue;
            }
            if c == '/' && self.peek(1) == Some('*') {
                self.pos += 2;
                while self.pos + 1 < self.chars.len() {
                    if self.chars[self.pos] == '\n' {
                        self.line += 1;
                    }
                    if self.chars[self.pos] == '*' && self.chars[self.pos + 1] == '/' {
                        self.pos += 2;
                        break;
                    }
                    self.pos += 1;
                }
                continue;
            }

            let line = self.line;
            if c == '"' || c == '\'' {
                out.push(TjsToken {
                    kind: TjsTokenKind::String(self.lex_string(c)),
                    line,
                });
                continue;
            }
            if is_ident_start(c) {
                let start = self.pos;
                self.pos += 1;
                while self.pos < self.chars.len() && is_ident_continue(self.chars[self.pos]) {
                    self.pos += 1;
                }
                out.push(TjsToken {
                    kind: TjsTokenKind::Ident(self.chars[start..self.pos].iter().collect()),
                    line,
                });
                continue;
            }
            if c.is_ascii_digit() {
                let start = self.pos;
                self.pos += 1;
                while self.pos < self.chars.len()
                    && (self.chars[self.pos].is_ascii_alphanumeric()
                        || matches!(self.chars[self.pos], '.' | 'x' | 'X'))
                {
                    self.pos += 1;
                }
                out.push(TjsToken {
                    kind: TjsTokenKind::Number(self.chars[start..self.pos].iter().collect()),
                    line,
                });
                continue;
            }
            if "()[]{}.,;:?".contains(c) {
                self.pos += 1;
                out.push(TjsToken {
                    kind: TjsTokenKind::Symbol(c),
                    line,
                });
                continue;
            }
            let mut op = String::new();
            op.push(c);
            if let Some(n) = self.peek(1) {
                let pair = [c, n].iter().collect::<String>();
                if matches!(
                    pair.as_str(),
                    "==" | "!="
                        | "<="
                        | ">="
                        | "&&"
                        | "||"
                        | "++"
                        | "--"
                        | "+="
                        | "-="
                        | "*="
                        | "/="
                        | "%="
                        | "=>"
                ) {
                    op.push(n);
                    self.pos += 2;
                } else {
                    self.pos += 1;
                }
            } else {
                self.pos += 1;
            }
            out.push(TjsToken {
                kind: TjsTokenKind::Operator(op),
                line,
            });
        }
        out
    }

    fn peek(&self, delta: usize) -> Option<char> {
        self.chars.get(self.pos + delta).copied()
    }

    fn lex_string(&mut self, quote: char) -> String {
        self.pos += 1;
        let mut out = String::new();
        while self.pos < self.chars.len() {
            let c = self.chars[self.pos];
            self.pos += 1;
            if c == quote {
                break;
            }
            if c == '\n' {
                self.line += 1;
            }
            if c != '\\' {
                out.push(c);
                continue;
            }
            if self.pos >= self.chars.len() {
                break;
            }
            let esc = self.chars[self.pos];
            self.pos += 1;
            match esc {
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                '0' => out.push('\0'),
                '\\' => out.push('\\'),
                '\'' => out.push('\''),
                '"' => out.push('"'),
                'x' => {
                    if let Some(v) = self.take_hex(2) {
                        if let Some(ch) = char::from_u32(v) {
                            out.push(ch);
                        }
                    }
                }
                'u' => {
                    if let Some(v) = self.take_hex(4) {
                        if let Some(ch) = char::from_u32(v) {
                            out.push(ch);
                        }
                    }
                }
                other => out.push(other),
            }
        }
        out
    }

    fn take_hex(&mut self, n: usize) -> Option<u32> {
        if self.pos + n > self.chars.len() {
            return None;
        }
        let s: String = self.chars[self.pos..self.pos + n].iter().collect();
        let value = u32::from_str_radix(&s, 16).ok()?;
        self.pos += n;
        Some(value)
    }
}

fn is_ident_start(c: char) -> bool {
    c == '_' || c == '$' || c.is_alphabetic() || !c.is_ascii()
}
fn is_ident_continue(c: char) -> bool {
    is_ident_start(c) || c.is_ascii_digit()
}

fn parse_tjs_references(src: &str) -> Vec<ScriptReference> {
    let tokens = TjsLexer::new(src).lex();
    let mut refs = Vec::new();

    // Every literal is useful, but preserve contextual call/assignment labels
    // so candidate expansion can infer omitted extensions conservatively.
    for token in &tokens {
        if let TjsTokenKind::String(value) = &token.kind {
            push_ref(&mut refs, token.line, "literal", value);
        }
    }

    for i in 0..tokens.len() {
        // identifier/property-chain(...): collect string arguments at depth 1.
        if !matches!(tokens[i].kind, TjsTokenKind::Symbol('(')) {
            continue;
        }
        let callee = callee_before(&tokens, i);
        if callee.is_empty() {
            continue;
        }
        let mut depth = 1usize;
        let mut j = i + 1;
        while j < tokens.len() && depth > 0 {
            match &tokens[j].kind {
                TjsTokenKind::Symbol('(') => depth += 1,
                TjsTokenKind::Symbol(')') => depth -= 1,
                TjsTokenKind::String(value) if depth == 1 => {
                    push_ref(&mut refs, tokens[j].line, &format!("call:{callee}"), value);
                }
                _ => {}
            }
            j += 1;
        }
    }

    // key = "value" and key: "value" capture storage-like properties.
    for i in 0..tokens.len().saturating_sub(2) {
        let key = match &tokens[i].kind {
            TjsTokenKind::Ident(v) => v,
            TjsTokenKind::String(v) => v,
            _ => continue,
        };
        let is_assign = matches!(&tokens[i + 1].kind, TjsTokenKind::Operator(op) if op == "=")
            || matches!(tokens[i + 1].kind, TjsTokenKind::Symbol(':'));
        if !is_assign {
            continue;
        }
        if let TjsTokenKind::String(value) = &tokens[i + 2].kind {
            push_ref(
                &mut refs,
                tokens[i + 2].line,
                &format!("field:{key}"),
                value,
            );
        }
    }

    // Constant string concatenations are common when scripts construct a path.
    // Fold maximal "a" + "b" (+ "c") runs without trying to evaluate code.
    let mut i = 0usize;
    while i < tokens.len() {
        let TjsTokenKind::String(first) = &tokens[i].kind else {
            i += 1;
            continue;
        };
        let mut joined = first.clone();
        let line = tokens[i].line;
        let mut j = i;
        let mut pieces = 1usize;
        while j + 2 < tokens.len()
            && matches!(&tokens[j + 1].kind, TjsTokenKind::Operator(op) if op == "+")
        {
            if let TjsTokenKind::String(next) = &tokens[j + 2].kind {
                joined.push_str(next);
                pieces += 1;
                j += 2;
            } else {
                break;
            }
        }
        if pieces > 1 {
            push_ref(&mut refs, line, "concat", &joined);
        }
        i = j + 1;
    }

    dedup_refs(refs)
}

fn callee_before(tokens: &[TjsToken], open: usize) -> String {
    if open == 0 {
        return String::new();
    }
    let mut parts = Vec::<String>::new();
    let mut i = open;
    while i > 0 {
        i -= 1;
        match &tokens[i].kind {
            TjsTokenKind::Ident(v) => parts.push(v.clone()),
            TjsTokenKind::Symbol('.') => parts.push(".".to_string()),
            _ => break,
        }
    }
    parts.reverse();
    let s = parts.concat();
    if s.ends_with('.') {
        String::new()
    } else {
        s
    }
}

fn push_ref(out: &mut Vec<ScriptReference>, line: usize, context: &str, value: &str) {
    let value = value.trim().trim_matches('\0');
    if value.is_empty() || value.chars().count() > 512 {
        return;
    }
    if value
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\t' | '\r' | '\n'))
    {
        return;
    }
    out.push(ScriptReference {
        line,
        context: context.to_string(),
        value: value.to_string(),
    });
}

fn dedup_refs(input: Vec<ScriptReference>) -> Vec<ScriptReference> {
    let mut seen = HashSet::new();
    input
        .into_iter()
        .filter(|r| seen.insert((r.line, r.context.clone(), r.value.clone())))
        .collect()
}

#[derive(Clone, Debug)]
struct EmbeddedTjs {
    text: String,
}

struct KagParser<'a> {
    src: &'a str,
    embedded_tjs: Vec<EmbeddedTjs>,
    notes: Vec<String>,
}

impl<'a> KagParser<'a> {
    fn new(src: &'a str) -> Self {
        Self {
            src,
            embedded_tjs: Vec::new(),
            notes: Vec::new(),
        }
    }

    fn parse(&mut self) -> Vec<ScriptReference> {
        let mut refs = Vec::new();
        let mut in_iscript = false;
        let mut script = String::new();
        let mut script_start_line = 1usize;

        for (zero_line, raw) in self.src.lines().enumerate() {
            let line_no = zero_line + 1;
            let trimmed = raw.trim_start();
            if in_iscript {
                if is_kag_end_iscript(trimmed) {
                    self.embedded_tjs.push(EmbeddedTjs {
                        text: std::mem::take(&mut script),
                    });
                    in_iscript = false;
                    continue;
                }
                script.push_str(raw);
                script.push('\n');
                continue;
            }
            if trimmed.starts_with(';') {
                continue;
            }
            if is_kag_start_iscript(trimmed) {
                in_iscript = true;
                script_start_line = line_no;
                continue;
            }

            for tag in lex_kag_tags(raw, line_no) {
                for (key, value) in tag.attrs {
                    let context = format!("kag:{}:{}", tag.name, key);
                    push_ref(&mut refs, line_no, &context, &value);
                }
            }
        }
        if in_iscript {
            self.notes.push(format!(
                "unterminated [iscript] beginning near line {script_start_line}"
            ));
            if !script.is_empty() {
                self.embedded_tjs.push(EmbeddedTjs { text: script });
            }
        }
        dedup_refs(refs)
    }
}

#[derive(Clone, Debug)]
struct KagTag {
    name: String,
    attrs: Vec<(String, String)>,
}

fn is_kag_start_iscript(line: &str) -> bool {
    let l = line.to_ascii_lowercase();
    l.starts_with("[iscript") || l.starts_with("@iscript")
}
fn is_kag_end_iscript(line: &str) -> bool {
    let l = line.to_ascii_lowercase();
    l.starts_with("[endscript") || l.starts_with("@endscript")
}

fn lex_kag_tags(line: &str, _line_no: usize) -> Vec<KagTag> {
    let chars: Vec<char> = line.chars().collect();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i] == '@' && (i == 0 || chars[..i].iter().all(|c| c.is_whitespace())) {
            let body: String = chars[i + 1..].iter().collect();
            if let Some(tag) = parse_kag_tag_body(&body) {
                out.push(tag);
            }
            break;
        }
        if chars[i] != '[' {
            i += 1;
            continue;
        }
        let start = i + 1;
        i += 1;
        let mut quote = None;
        while i < chars.len() {
            let c = chars[i];
            if let Some(q) = quote {
                if c == '\\' {
                    i = (i + 2).min(chars.len());
                    continue;
                }
                if c == q {
                    quote = None;
                }
            } else if c == '"' || c == '\'' {
                quote = Some(c);
            } else if c == ']' {
                break;
            }
            i += 1;
        }
        if i >= chars.len() {
            break;
        }
        let body: String = chars[start..i].iter().collect();
        if let Some(tag) = parse_kag_tag_body(&body) {
            out.push(tag);
        }
        i += 1;
    }
    out
}

fn parse_kag_tag_body(body: &str) -> Option<KagTag> {
    let chars: Vec<char> = body.chars().collect();
    let mut i = 0usize;
    skip_ws(&chars, &mut i);
    let name = read_kag_word(&chars, &mut i);
    if name.is_empty() {
        return None;
    }
    let mut attrs = Vec::new();
    while i < chars.len() {
        skip_ws(&chars, &mut i);
        if i >= chars.len() {
            break;
        }
        let key = read_kag_word(&chars, &mut i);
        if key.is_empty() {
            i += 1;
            continue;
        }
        skip_ws(&chars, &mut i);
        if i >= chars.len() || chars[i] != '=' {
            attrs.push((key, "true".to_string()));
            continue;
        }
        i += 1;
        skip_ws(&chars, &mut i);
        let value = read_kag_value(&chars, &mut i);
        attrs.push((key, value));
    }
    Some(KagTag {
        name: name.to_ascii_lowercase(),
        attrs,
    })
}

fn skip_ws(chars: &[char], i: &mut usize) {
    while *i < chars.len() && chars[*i].is_whitespace() {
        *i += 1;
    }
}
fn read_kag_word(chars: &[char], i: &mut usize) -> String {
    let start = *i;
    while *i < chars.len() && !chars[*i].is_whitespace() && !matches!(chars[*i], '=' | '[' | ']') {
        *i += 1;
    }
    chars[start..*i].iter().collect()
}
fn read_kag_value(chars: &[char], i: &mut usize) -> String {
    if *i >= chars.len() {
        return String::new();
    }
    if chars[*i] == '"' || chars[*i] == '\'' {
        let quote = chars[*i];
        *i += 1;
        let mut out = String::new();
        while *i < chars.len() {
            let c = chars[*i];
            *i += 1;
            if c == quote {
                break;
            }
            if c == '\\' && *i < chars.len() {
                out.push(chars[*i]);
                *i += 1;
            } else {
                out.push(c);
            }
        }
        out
    } else {
        let start = *i;
        while *i < chars.len() && !chars[*i].is_whitespace() {
            *i += 1;
        }
        chars[start..*i].iter().collect()
    }
}

fn references_to_candidates(refs: &[ScriptReference]) -> HashSet<String> {
    let mut out = HashSet::new();
    for r in refs {
        add_reference_candidates(&mut out, &r.value, &r.context);
    }
    out
}

fn add_reference_candidates(out: &mut HashSet<String>, value: &str, context: &str) {
    let mut value = value.trim().trim_matches('\0').replace('\\', "/");
    if value.is_empty() || value.len() > 1024 {
        return;
    }
    while value.starts_with("./") {
        value.drain(..2);
    }
    for prefix in ["file://", "storage://"] {
        if value.to_ascii_lowercase().starts_with(prefix) {
            value = value[prefix.len()..].to_string();
        }
    }
    if let Some((before, _)) = value.split_once('?') {
        value = before.to_string();
    }
    if let Some((before, _)) = value.split_once('#') {
        value = before.to_string();
    }
    let mut bases = vec![value.clone()];
    if let Some((_, after)) = value.rsplit_once('>') {
        if !after.is_empty() {
            bases.push(after.to_string());
        }
    }
    if let Some(stripped) = value.strip_prefix('/') {
        if !stripped.is_empty() {
            bases.push(stripped.to_string());
        }
    }

    let ctx = context.to_ascii_lowercase();
    let mut ext_hints: Vec<&str> = Vec::new();
    if ctx.contains("tjs")
        || ctx.contains("execstorage")
        || ctx.contains("include")
        || ctx.contains("require")
        || ctx.contains("plugin")
    {
        ext_hints.push("tjs");
    }
    if ctx.contains("scenario")
        || ctx.contains("jump")
        || ctx.contains("call")
        || ctx.contains("kag")
        || ctx.contains("ks")
    {
        ext_hints.push("ks");
    }
    if ctx.contains("image")
        || ctx.contains("graphic")
        || ctx.contains("face")
        || ctx.contains("layer")
        || ctx.contains("background")
        || ctx.contains("kag:bg")
    {
        ext_hints.extend(["tlg", "png", "jpg"]);
    }
    if ctx.contains("voice")
        || ctx.contains("bgm")
        || ctx.contains("sound")
        || ctx.contains("playse")
        || ctx.contains("audio")
    {
        ext_hints.extend(["ogg", "opus", "wav"]);
    }
    if ctx.contains("movie") || ctx.contains("video") {
        ext_hints.extend(["mpg", "mp4", "wmv"]);
    }
    if ctx.contains("storage") && ext_hints.is_empty() {
        ext_hints.extend(["tjs", "ks", "tlg", "png", "ogg", "opus"]);
    }

    for base in bases {
        let base = base
            .trim()
            .trim_matches(|c: char| matches!(c, '"' | '\'' | '[' | ']' | '{' | '}'))
            .to_string();
        if !plausible_storage_atom(&base) {
            continue;
        }
        out.insert(base.clone());
        if let Some(name) = base.rsplit('/').next() {
            if name != base {
                out.insert(name.to_string());
            }
        }
        if !has_extension(&base) {
            for ext in &ext_hints {
                out.insert(format!("{base}.{ext}"));
            }
        }
    }
}

fn plausible_storage_atom(value: &str) -> bool {
    if value.is_empty() || value.chars().count() > 240 {
        return false;
    }
    if value.chars().any(|c| c.is_control()) {
        return false;
    }
    let lower = value.to_ascii_lowercase();
    if matches!(lower.as_str(), "true" | "false" | "null" | "void") {
        return false;
    }
    value.contains('.')
        || value.contains('/')
        || value.contains('>')
        || value
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | '+' | '@' | '~' | ' '))
}

fn has_extension(value: &str) -> bool {
    value.rsplit('/').next().is_some_and(|name| {
        name.rsplit_once('.')
            .is_some_and(|(stem, ext)| !stem.is_empty() && (1..=8).contains(&ext.len()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tjs_parser_keeps_call_and_assignment_context() {
        let src = r#"
            System.execStorage("initialize.tjs");
            var scenario = "scenario/" + "first.ks";
            storage = "option";
        "#;
        let refs = parse_tjs_references(src);
        assert!(refs
            .iter()
            .any(|r| r.context == "call:System.execStorage" && r.value == "initialize.tjs"));
        assert!(refs
            .iter()
            .any(|r| r.context == "concat" && r.value == "scenario/first.ks"));
        assert!(refs
            .iter()
            .any(|r| r.context == "field:storage" && r.value == "option"));
        let candidates = references_to_candidates(&refs);
        assert!(candidates.contains("initialize.tjs"));
        assert!(candidates.contains("scenario/first.ks"));
        assert!(candidates.contains("option.tjs"));
        assert!(candidates.contains("option.ks"));
    }

    #[test]
    fn kag_parser_extracts_storage_and_embedded_tjs() {
        let src = r#"
; comment
[image storage="ev/scene01.tlg" layer=base]
@jump storage=next.ks target=*start
[iscript]
System.execStorage("plugin.tjs");
[endscript]
"#;
        let report = analyze_kag(src.as_bytes());
        assert!(report
            .references
            .iter()
            .any(|r| r.value == "ev/scene01.tlg"));
        assert!(report.references.iter().any(|r| r.value == "next.ks"));
        assert!(report.references.iter().any(|r| r.value == "plugin.tjs"));
        assert!(report.candidates.contains("ev/scene01.tlg"));
        assert!(report.candidates.contains("next.ks"));
        assert!(report.candidates.contains("plugin.tjs"));
    }

    #[test]
    fn tjs_lexer_ignores_comments_and_unescapes_strings() {
        let src = "// \"ignored.ks\"\nvar x = \"scenario\\\\main.ks\"; /* 'also.ks' */";
        let refs = parse_tjs_references(src);
        assert!(refs.iter().any(|r| r.value == "scenario\\main.ks"));
        assert!(!refs
            .iter()
            .any(|r| r.value == "ignored.ks" || r.value == "also.ks"));
    }
}
