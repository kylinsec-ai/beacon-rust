//! 获取和设置 Beacon 设置的 API（settings.cpp）。
//! API to retrieve and set Beacon settings (settings.cpp).
//!
//! 在原始构建中，团队服务器将 `myargs`（一个 4096 字节的配置块，用 0x2E 进行 XOR 混淆）直接打入 DLL 映像。`settings_init` 解除掩码、解析设置表，然后将其清零。
//! In the original build the team server patches `myargs` (a 4096-byte
//! config blob, XOR-obfuscated with 0x2E) directly into the DLL image.
//! `settings_init` unmasks it, parses the settings table, then zeroes it.
//!
//! 设置表是进程生命周期的配置：只填充一次（DLL_PROCESS_ATTACH），之后只读，因此它存放在 `OnceLock` 中。C++ 字符串设置（`char*`）建模为自有的 `Vec<u8>` 值；`setting_ptr` 返回锁持有表内的 `'static` 切片。
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

/// 植入 `myargs` 块（供测试/工具使用）。真实构建直接修补 DLL 映像。
/// Seed the `myargs` blob (used by tests / tooling). The real build patches
/// the DLL image directly.
pub fn seed_myargs(blob: &[u8]) {
    crate::settings_util::set_myargs(blob);
}

/// 按 id 读取一个设置项。
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

/// 测试 SHORT 设置中是否设置了某个标志位。
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

/// 解析打入的 `myargs` 块到设置表中。
/// Parse the patched `myargs` blob into the settings table.
pub fn settings_init(bptr: usize) {
    if SETTINGS.get().is_some() {
        return;
    }
    let _ = BEACON_PTR.set(bptr);

    let mut myargs = crate::settings_util::take_myargs();
    // 解除 myargs 掩码
    // unmask myargs
    for x in 0..myargs.len() {
        myargs[x] ^= 0x2E;
    }

    let mut table = SettingsTable::default();
    {
        let mut parser = DataP::init(&mut myargs[..]);
        // 遍历 myargs 并填充 settings[id]
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

/// 仅测试：从新块强制重新初始化（重置表）。
/// Test-only: force re-init from a fresh blob (resets the table).
#[cfg(test)]
pub fn settings_init_for_test(bptr: usize) {
    crate::settings_util::reset_for_test();
    settings_init(bptr);
}
