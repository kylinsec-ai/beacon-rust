//! Beacon core library — Rust port of the Cobalt Strike Beacon C++ source.
//!
//! Mirrors the module layout of `src/*.cpp`. Each module is documented with
//! the C++ file it ports. Wire formats and crypto are byte-compatible with
//! the original (AES-128-CBC + truncated HMAC-SHA256, RSA PKCS#1 v1.5,
//! Malleable C2 transforms).
//!
//! The C API is mirrored function-for-function: many `command_*(buffer,
//! length)` signatures keep parameters that the C++ also ignores (bounds
//! checks or empty bodies). Those intentional mirrors trigger
//! `unused_variables`; the allows below are scoped to the port's API shape.
#![allow(unused_variables)]
#![allow(unused_assignments)]
#![allow(unused_mut)]

pub mod argue;
pub mod beacon;
pub mod bformat;
pub mod boff;
pub mod build;
pub mod callback;
pub mod channel;
pub mod channel_tcp;
pub mod client;
pub mod client_smb;
pub mod client_smb_extc2;
pub mod client_tcp;
pub mod commands;
pub mod elevate;
pub mod encoders;
pub mod files;
pub mod filesys;
pub mod functions;
pub mod gargle;
pub mod gargle_pivot_smb;
pub mod gargle_pivot_tcp;
pub mod gargleint;
pub mod hotbeef;
pub mod inject;
pub mod inject_apcthread;
pub mod inject_createthread;
pub mod inject_hinted;
pub mod inject_mirror;
pub mod inject_rtlcreateuserthread;
pub mod inject_rtlcreateuserthread_wow64;
pub mod inject_setthreadcontext;
pub mod inject_smart;
pub mod inlineexec;
pub mod jobs;
pub mod link;
pub mod link_smb;
pub mod link_tcp;
pub mod metadata;
pub mod parse;
pub mod pivot;
pub mod powershell;
pub mod process;
pub mod profile;
pub mod proto;
pub mod ps;
pub mod recurse;
pub mod security;
pub mod settings;
pub mod settings_util;
pub mod state;
pub mod strategy;
pub mod thread;
pub mod tokens;
pub mod track_memory;
pub mod webserver;
