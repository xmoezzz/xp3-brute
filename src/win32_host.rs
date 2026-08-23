//! CPU-backend-independent Win32 host state for the constrained PE32 runner.
//!
//! The separation between typed API dispatch, process/module state, and
//! per-thread TLS/last-error state is adapted from retrowin32's `win32/`
//! implementation (Apache-2.0). This file is a substantially modified,
//! intentionally narrow implementation for Kirikiri TPM initialization; see
//! `third_party/retrowin32/NOTICE.md` and
//! `third_party/retrowin32/LICENSE-APACHE-2.0.txt`.

use encoding_rs::SHIFT_JIS;
use std::collections::{BTreeMap, HashMap};

pub(crate) const ERROR_SUCCESS: u32 = 0;
pub(crate) const ERROR_INVALID_PARAMETER: u32 = 87;
pub(crate) const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
pub(crate) const ERROR_MOD_NOT_FOUND: u32 = 126;
pub(crate) const ERROR_PROC_NOT_FOUND: u32 = 127;
pub(crate) const ERROR_NO_UNICODE_TRANSLATION: u32 = 1113;

pub(crate) const CP_ACP: u32 = 0;
pub(crate) const CP_OEMCP: u32 = 1;
pub(crate) const CP_THREAD_ACP: u32 = 3;
pub(crate) const CP_UTF8: u32 = 65_001;

pub(crate) const LOCALE_USER_DEFAULT: u32 = 0x0400;
pub(crate) const LOCALE_SYSTEM_DEFAULT: u32 = 0x0800;
pub(crate) const LOCALE_RETURN_NUMBER: u32 = 0x2000_0000;
pub(crate) const LOCALE_USE_CP_ACP: u32 = 0x4000_0000;
pub(crate) const LOCALE_NOUSEROVERRIDE: u32 = 0x8000_0000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Win32GuestProfile {
    pub user_lcid: u32,
    pub system_lcid: u32,
    pub ansi_code_page: u32,
    pub oem_code_page: u32,
}

impl Win32GuestProfile {
    pub(crate) const JAPANESE_WINDOWS: Self = Self {
        user_lcid: 0x0411,
        system_lcid: 0x0411,
        ansi_code_page: 932,
        oem_code_page: 932,
    };

    fn resolve_lcid(self, lcid: u32) -> Option<u32> {
        match lcid {
            LOCALE_USER_DEFAULT => Some(self.user_lcid),
            LOCALE_SYSTEM_DEFAULT => Some(self.system_lcid),
            0x0411 => Some(0x0411),
            _ => None,
        }
    }

    pub(crate) fn resolve_code_page(self, code_page: u32) -> Option<u32> {
        match code_page {
            CP_ACP | CP_THREAD_ACP => Some(self.ansi_code_page),
            CP_OEMCP => Some(self.oem_code_page),
            932 | CP_UTF8 => Some(code_page),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum LocaleInfoValue {
    Ansi(Vec<u8>),
    Number(u32),
}

#[derive(Clone, Debug)]
pub(crate) struct Win32ThreadState {
    pub last_error: u32,
    tls: BTreeMap<u32, u32>,
}

impl Default for Win32ThreadState {
    fn default() -> Self {
        Self {
            last_error: ERROR_SUCCESS,
            tls: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Win32HostState {
    pub profile: Win32GuestProfile,
    pub thread: Win32ThreadState,
    next_tls: u32,
    exports: HashMap<String, u32>,
    modules: HashMap<String, u32>,
    next_module_handle: u32,
    allocation_cursor: u64,
    allocation_limit: u64,
    allocations: BTreeMap<u64, usize>,
}

impl Default for Win32HostState {
    fn default() -> Self {
        Self::new(Win32GuestProfile::JAPANESE_WINDOWS)
    }
}

impl Win32HostState {
    pub(crate) fn new(profile: Win32GuestProfile) -> Self {
        Self {
            profile,
            thread: Win32ThreadState::default(),
            next_tls: 0,
            exports: HashMap::new(),
            modules: HashMap::new(),
            next_module_handle: 0x7331_0000,
            allocation_cursor: 0,
            allocation_limit: 0,
            allocations: BTreeMap::new(),
        }
    }

    pub(crate) fn configure_allocator(&mut self, base: u64, limit: u64) {
        self.allocation_cursor = base;
        self.allocation_limit = limit;
        self.allocations.clear();
    }

    pub(crate) fn allocate(&mut self, requested: usize) -> Option<u64> {
        let size = requested.max(1);
        let aligned = ((size as u64).saturating_add(0x0f) & !0x0f).max(0x10);
        loop {
            let end = self.allocation_cursor.checked_add(aligned)?;
            if end > self.allocation_limit {
                return None;
            }
            let overlap = self.allocations.iter().find_map(|(base, old_size)| {
                let old_end = base.saturating_add(*old_size as u64);
                (self.allocation_cursor < old_end && *base < end).then_some(old_end)
            });
            if let Some(next) = overlap {
                self.allocation_cursor = (next.saturating_add(0x0f)) & !0x0f;
                continue;
            }
            let pointer = self.allocation_cursor;
            self.allocation_cursor = end;
            self.allocations.insert(pointer, size);
            return Some(pointer);
        }
    }

    pub(crate) fn reserve(&mut self, pointer: u64, requested: usize) -> bool {
        let size = requested.max(1);
        let Some(end) = pointer.checked_add(size as u64) else {
            return false;
        };
        if pointer >= self.allocation_limit
            || end > self.allocation_limit
            || self.allocations.iter().any(|(base, old_size)| {
                let old_end = base.saturating_add(*old_size as u64);
                pointer < old_end && *base < end
            })
        {
            return false;
        }
        self.allocations.insert(pointer, size);
        true
    }

    pub(crate) fn free_allocation(&mut self, pointer: u64) -> bool {
        self.allocations.remove(&pointer).is_some()
    }

    pub(crate) fn allocation_size(&self, pointer: u64) -> Option<usize> {
        self.allocations.get(&pointer).copied()
    }

    pub(crate) fn allocation_snapshot(&self) -> Vec<(u64, usize)> {
        self.allocations
            .iter()
            .map(|(pointer, size)| (*pointer, *size))
            .collect()
    }

    pub(crate) fn set_last_error(&mut self, error: u32) {
        self.thread.last_error = error;
    }

    pub(crate) fn last_error(&self) -> u32 {
        self.thread.last_error
    }

    pub(crate) fn register_export(&mut self, name: impl Into<String>, address: u32) {
        self.exports.insert(name.into(), address);
    }

    pub(crate) fn resolve_export(&self, name: &str) -> Option<u32> {
        self.exports.get(name).copied()
    }

    pub(crate) fn load_module(&mut self, name: &str) -> u32 {
        let normalized = normalize_module_name(name);
        if let Some(handle) = self.modules.get(&normalized) {
            return *handle;
        }
        let handle = self.next_module_handle;
        self.next_module_handle = self.next_module_handle.saturating_add(0x1_0000);
        self.modules.insert(normalized, handle);
        handle
    }

    pub(crate) fn module_handle(&self, name: &str) -> Option<u32> {
        self.modules.get(&normalize_module_name(name)).copied()
    }

    pub(crate) fn tls_alloc(&mut self) -> u32 {
        let index = self.next_tls;
        self.next_tls = self.next_tls.saturating_add(1);
        self.thread.tls.insert(index, 0);
        index
    }

    pub(crate) fn tls_free(&mut self, index: u32) -> bool {
        let removed = self.thread.tls.remove(&index).is_some();
        if !removed {
            self.set_last_error(ERROR_INVALID_PARAMETER);
        }
        removed
    }

    pub(crate) fn tls_get(&mut self, index: u32) -> Option<u32> {
        let value = self.thread.tls.get(&index).copied();
        if value.is_some() {
            // Windows documents that callers must clear last-error before
            // TlsGetValue when zero is a meaningful stored value.
            self.set_last_error(ERROR_SUCCESS);
        } else {
            self.set_last_error(ERROR_INVALID_PARAMETER);
        }
        value
    }

    pub(crate) fn tls_set(&mut self, index: u32, value: u32) -> bool {
        let Some(slot) = self.thread.tls.get_mut(&index) else {
            self.set_last_error(ERROR_INVALID_PARAMETER);
            return false;
        };
        *slot = value;
        true
    }

    pub(crate) fn locale_info_a(
        &mut self,
        locale: u32,
        locale_type: u32,
    ) -> Option<LocaleInfoValue> {
        let Some(locale) = self.profile.resolve_lcid(locale) else {
            self.set_last_error(ERROR_INVALID_PARAMETER);
            return None;
        };
        let flags =
            locale_type & (LOCALE_RETURN_NUMBER | LOCALE_USE_CP_ACP | LOCALE_NOUSEROVERRIDE);
        let kind =
            locale_type & !(LOCALE_RETURN_NUMBER | LOCALE_USE_CP_ACP | LOCALE_NOUSEROVERRIDE);
        if locale != 0x0411 {
            self.set_last_error(ERROR_INVALID_PARAMETER);
            return None;
        }

        // Values are the stable Japanese (Japan) defaults used by legacy
        // Windows/Kirikiri runtimes. All strings include their terminating NUL.
        let text = match kind {
            0x0000_0001 => "0411",                     // LOCALE_ILANGUAGE
            0x0000_0002 => "Japanese",                 // LOCALE_SLANGUAGE
            0x0000_0003 => "Japanese",                 // LOCALE_SENGLANGUAGE
            0x0000_0004 => "JPN",                      // LOCALE_SABBREVLANGNAME
            0x0000_0005 => "\u{65e5}\u{672c}\u{8a9e}", // LOCALE_SNATIVELANGNAME
            0x0000_0006 => "81",                       // LOCALE_ICOUNTRY
            0x0000_0007 => "Japan",                    // LOCALE_SCOUNTRY
            0x0000_0009 => "0411",                     // LOCALE_IDEFAULTLANGUAGE
            0x0000_000b => "932",                      // LOCALE_IDEFAULTCODEPAGE
            0x0000_000e => ".",                        // LOCALE_SDECIMAL
            0x0000_000f => ",",                        // LOCALE_STHOUSAND
            0x0000_0010 => "3;0",                      // LOCALE_SGROUPING
            0x0000_001d => "yyyy/MM/dd",               // LOCALE_SLONGDATE
            0x0000_001f => "yyyy/MM/dd",               // LOCALE_SSHORTDATE
            0x0000_0020 => "HH:mm:ss",                 // LOCALE_STIMEFORMAT
            0x0000_0059 => "ja",                       // LOCALE_SISO639LANGNAME
            0x0000_005a => "JP",                       // LOCALE_SISO3166CTRYNAME
            0x0000_1001 => "Japanese",                 // LOCALE_SENGLANGUAGE (new value)
            0x0000_1002 => "Japan",                    // LOCALE_SENGCOUNTRY
            0x0000_1004 => "932",                      // LOCALE_IDEFAULTANSICODEPAGE
            0x0000_1005 => "10001",                    // LOCALE_IDEFAULTMACCODEPAGE
            0x0000_1006 => "20290",                    // LOCALE_IDEFAULTEBCDICCODEPAGE
            0x0000_005c => "ja-JP",                    // LOCALE_SNAME
            _ => {
                self.set_last_error(ERROR_INVALID_PARAMETER);
                return None;
            }
        };

        self.set_last_error(ERROR_SUCCESS);
        if flags & LOCALE_RETURN_NUMBER != 0 {
            let number = text.parse::<u32>().ok().or(match kind {
                0x0000_0001 | 0x0000_0009 => Some(0x0411),
                _ => None,
            });
            let Some(number) = number else {
                self.set_last_error(ERROR_INVALID_PARAMETER);
                return None;
            };
            return Some(LocaleInfoValue::Number(number));
        }

        let code_page = if flags & LOCALE_USE_CP_ACP != 0 {
            self.profile.ansi_code_page
        } else {
            932
        };
        let mut bytes = encode_ansi(code_page, text).ok()?;
        bytes.push(0);
        Some(LocaleInfoValue::Ansi(bytes))
    }
}

fn normalize_module_name(name: &str) -> String {
    let mut normalized = name.replace('/', "\\").to_ascii_lowercase();
    if let Some(base) = normalized.rsplit('\\').next() {
        normalized = base.to_string();
    }
    if !normalized.ends_with(".dll") && !normalized.ends_with(".exe") {
        normalized.push_str(".dll");
    }
    normalized
}

pub(crate) fn decode_ansi(code_page: u32, input: &[u8], strict: bool) -> Result<Vec<u16>, u32> {
    let text = match code_page {
        932 => {
            let (text, had_errors) = SHIFT_JIS.decode_without_bom_handling(input);
            if strict && had_errors {
                return Err(ERROR_NO_UNICODE_TRANSLATION);
            }
            text
        }
        CP_UTF8 => {
            let text = String::from_utf8_lossy(input);
            if strict && matches!(text, std::borrow::Cow::Owned(_)) {
                return Err(ERROR_NO_UNICODE_TRANSLATION);
            }
            text
        }
        _ => return Err(ERROR_INVALID_PARAMETER),
    };
    Ok(text.encode_utf16().collect())
}

pub(crate) fn encode_ansi(code_page: u32, input: &str) -> Result<Vec<u8>, u32> {
    encode_ansi_with_default(code_page, input).map(|(bytes, _)| bytes)
}

pub(crate) fn encode_ansi_with_default(
    code_page: u32,
    input: &str,
) -> Result<(Vec<u8>, bool), u32> {
    match code_page {
        932 => {
            let (bytes, _, had_errors) = SHIFT_JIS.encode(input);
            Ok((bytes.into_owned(), had_errors))
        }
        CP_UTF8 => Ok((input.as_bytes().to_vec(), false)),
        _ => Err(ERROR_INVALID_PARAMETER),
    }
}

#[derive(Clone, Debug)]
pub(crate) enum Win32Api {
    VirtualAlloc,
    VirtualQuery,
    VirtualFree,
    VirtualProtect,
    HeapAlloc,
    HeapReAlloc,
    HeapFree,
    HeapSize,
    HeapCreate,
    HeapDestroy,
    GetProcessHeap,
    LoadLibrary,
    LoadLibraryEx,
    FreeLibrary,
    GetProcAddress,
    GetModuleHandle,
    GetModuleFileNameA,
    GetModuleFileNameW,
    GetCurrentProcess,
    GetCurrentProcessId,
    GetCurrentThreadId,
    GetTickCount,
    QueryPerformanceCounter,
    IsDebuggerPresent,
    Sleep,
    TlsAlloc,
    FlsAlloc,
    TlsGetValue,
    TlsSetValue,
    TlsFree,
    CriticalSection,
    CriticalSectionSpin,
    CriticalSectionEx,
    Memcpy,
    Memmove,
    Memset,
    Malloc,
    Calloc,
    Realloc,
    Free,
    Unknown(String),
}

impl Win32Api {
    pub(crate) fn from_name(name: &str) -> Self {
        match name {
            "VirtualAlloc" => Self::VirtualAlloc,
            "VirtualQuery" => Self::VirtualQuery,
            "VirtualFree" => Self::VirtualFree,
            "VirtualProtect" => Self::VirtualProtect,
            "HeapAlloc" => Self::HeapAlloc,
            "HeapReAlloc" => Self::HeapReAlloc,
            "HeapFree" => Self::HeapFree,
            "HeapSize" => Self::HeapSize,
            "HeapCreate" => Self::HeapCreate,
            "HeapDestroy" => Self::HeapDestroy,
            "GetProcessHeap" => Self::GetProcessHeap,
            "LoadLibraryA" | "LoadLibraryW" => Self::LoadLibrary,
            "LoadLibraryExA" | "LoadLibraryExW" => Self::LoadLibraryEx,
            "FreeLibrary" => Self::FreeLibrary,
            "GetProcAddress" => Self::GetProcAddress,
            "GetModuleHandleA" | "GetModuleHandleW" => Self::GetModuleHandle,
            "GetModuleFileNameA" => Self::GetModuleFileNameA,
            "GetModuleFileNameW" => Self::GetModuleFileNameW,
            "GetCurrentProcess" => Self::GetCurrentProcess,
            "GetCurrentProcessId" => Self::GetCurrentProcessId,
            "GetCurrentThreadId" => Self::GetCurrentThreadId,
            "GetTickCount" => Self::GetTickCount,
            "QueryPerformanceCounter" => Self::QueryPerformanceCounter,
            "IsDebuggerPresent" => Self::IsDebuggerPresent,
            "Sleep" => Self::Sleep,
            "TlsAlloc" => Self::TlsAlloc,
            "FlsAlloc" => Self::FlsAlloc,
            "TlsGetValue" | "FlsGetValue" => Self::TlsGetValue,
            "TlsSetValue" | "FlsSetValue" => Self::TlsSetValue,
            "TlsFree" | "FlsFree" => Self::TlsFree,
            "InitializeCriticalSection"
            | "DeleteCriticalSection"
            | "EnterCriticalSection"
            | "LeaveCriticalSection"
            | "TryEnterCriticalSection" => Self::CriticalSection,
            "InitializeCriticalSectionAndSpinCount" => Self::CriticalSectionSpin,
            "InitializeCriticalSectionEx" => Self::CriticalSectionEx,
            "memcpy" | "_memcpy" => Self::Memcpy,
            "memmove" | "_memmove" => Self::Memmove,
            "memset" | "_memset" => Self::Memset,
            "malloc" | "_malloc" => Self::Malloc,
            "calloc" | "_calloc" => Self::Calloc,
            "realloc" | "_realloc" => Self::Realloc,
            "free" | "_free" => Self::Free,
            other => Self::Unknown(other.to_string()),
        }
    }

    pub(crate) fn stack_bytes(&self) -> u16 {
        match self {
            Self::VirtualAlloc | Self::VirtualProtect | Self::HeapReAlloc => 16,
            Self::VirtualQuery
            | Self::VirtualFree
            | Self::HeapAlloc
            | Self::HeapCreate
            | Self::HeapFree
            | Self::HeapSize
            | Self::LoadLibraryEx
            | Self::GetModuleFileNameA
            | Self::GetModuleFileNameW => 12,
            Self::GetProcAddress | Self::TlsSetValue | Self::CriticalSectionSpin => 8,
            Self::GetProcessHeap
            | Self::GetCurrentProcess
            | Self::GetCurrentProcessId
            | Self::GetCurrentThreadId
            | Self::GetTickCount
            | Self::IsDebuggerPresent
            | Self::TlsAlloc => 0,
            Self::HeapDestroy
            | Self::LoadLibrary
            | Self::FreeLibrary
            | Self::GetModuleHandle
            | Self::QueryPerformanceCounter
            | Self::Sleep
            | Self::FlsAlloc
            | Self::TlsGetValue
            | Self::TlsFree
            | Self::CriticalSection => 4,
            Self::CriticalSectionEx => 12,
            Self::Memcpy
            | Self::Memmove
            | Self::Memset
            | Self::Malloc
            | Self::Calloc
            | Self::Realloc
            | Self::Free => 0,
            Self::Unknown(name) => unknown_stack_bytes(name),
        }
    }
}

fn unknown_stack_bytes(name: &str) -> u16 {
    match name {
        "GetEnvironmentStrings"
        | "GetEnvironmentStringsA"
        | "GetEnvironmentStringsW"
        | "GetCommandLineA"
        | "GetVersion"
        | "GetLastError"
        | "GetACP"
        | "GetOEMCP"
        | "GetConsoleCP"
        | "GetConsoleOutputCP"
        | "GetUserDefaultLCID"
        | "GetSystemDefaultLCID"
        | "GetThreadLocale" => 0,
        "InterlockedDecrement"
        | "InterlockedIncrement"
        | "CloseHandle"
        | "SetLastError"
        | "SetUnhandledExceptionFilter"
        | "ExitProcess"
        | "SetHandleCount"
        | "GetStdHandle"
        | "GetFileType"
        | "GetStartupInfoA"
        | "GetStartupInfoW"
        | "FreeEnvironmentStringsA"
        | "FreeEnvironmentStringsW"
        | "GetVersionExA"
        | "GetSystemTimeAsFileTime"
        | "IsProcessorFeaturePresent"
        | "EncodePointer"
        | "DecodePointer"
        | "FlushFileBuffers"
        | "IsBadCodePtr"
        | "SetEndOfFile"
        | "IsValidCodePage"
        | "IsDBCSLeadByte" => 4,
        "TerminateProcess" | "IsBadWritePtr" | "IsBadReadPtr" | "GetCPInfo" | "SetStdHandle"
        | "IsValidLocale" | "IsDBCSLeadByteEx" => 8,
        "GetEnvironmentVariableA" => 12,
        "GetLocaleInfoA" | "GetLocaleInfoW" | "RtlUnwind" | "RaiseException" | "SetFilePointer"
        | "GetStringTypeW" => 16,
        "ReadFile" | "WriteFile" | "GetStringTypeA" => 20,
        "MultiByteToWideChar" | "LCMapStringA" | "LCMapStringW" => 24,
        "CreateFileA" => 28,
        "WideCharToMultiByte" => 32,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn japanese_profile_exposes_lcid_acp_and_cp932_locale_info() {
        let mut host = Win32HostState::default();
        assert_eq!(host.profile.user_lcid, 0x0411);
        assert_eq!(host.profile.ansi_code_page, 932);
        assert_eq!(
            host.locale_info_a(0x0411, 0x1004),
            Some(LocaleInfoValue::Ansi(b"932\0".to_vec()))
        );
        assert_eq!(
            host.locale_info_a(LOCALE_USER_DEFAULT, 0x1004 | LOCALE_RETURN_NUMBER),
            Some(LocaleInfoValue::Number(932))
        );
    }

    #[test]
    fn cp932_conversion_round_trips_japanese_text() {
        let original = "\u{65e5}\u{672c}\u{8a9e}";
        let encoded = encode_ansi(932, original).unwrap();
        assert_eq!(encoded, [0x93, 0xfa, 0x96, 0x7b, 0x8c, 0xea]);
        let wide = decode_ansi(932, &encoded, true).unwrap();
        assert_eq!(String::from_utf16(&wide).unwrap(), original);
    }

    #[test]
    fn tls_and_last_error_are_thread_state_not_api_stubs() {
        let mut host = Win32HostState::default();
        let slot = host.tls_alloc();
        assert!(host.tls_set(slot, 0x1234_5678));
        assert_eq!(host.tls_get(slot), Some(0x1234_5678));
        assert_eq!(host.last_error(), ERROR_SUCCESS);
        assert_eq!(host.tls_get(slot + 1), None);
        assert_eq!(host.last_error(), ERROR_INVALID_PARAMETER);
    }

    #[test]
    fn module_exports_and_tls_indexes_are_validated() {
        let mut host = Win32HostState::default();
        let kernel = host.load_module("C:/Windows/System32/KERNEL32.DLL");
        assert_eq!(host.module_handle("kernel32"), Some(kernel));
        host.register_export("GetLocaleInfoA", 0x7000_1234);
        assert_eq!(host.resolve_export("GetLocaleInfoA"), Some(0x7000_1234));

        let slot = host.tls_alloc();
        assert!(host.tls_free(slot));
        assert!(!host.tls_free(slot));
        assert_eq!(host.last_error(), ERROR_INVALID_PARAMETER);
    }
}
