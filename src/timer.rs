//! Port of timer.c: named Lua timers in insertion order (uthash), run from the main loop.

use crate::dlog;
use crate::helpers::boottime_ms;
use crate::params::params;
use std::cell::Cell;

pub struct Timer {
    pub func_ref: i32,
    pub lua_ref: i32,
    pub period: u64,
    pub oneshot: bool,
    pub bt_next: u64,
    pub n: u32,
    pub fires: u32,
}

impl Drop for Timer {
    fn drop(&mut self) {
        crate::lua::unref(self.lua_ref);
        crate::lua::unref(self.func_ref);
    }
}

#[derive(Default)]
pub struct TimerPool(pub crate::pools::IMap<String, Timer>);

thread_local! {
    static TIMER_N: Cell<u32> = const { Cell::new(0) };
}

impl TimerPool {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn add(&mut self, name: &str, period: u64, oneshot: bool) -> &mut Timer {
        let n = TIMER_N.with(|c| {
            c.set(c.get().wrapping_add(1));
            c.get()
        });
        self.0.insert(
            name.to_string(),
            Timer {
                func_ref: crate::lua::lj::LUA_NOREF,
                lua_ref: crate::lua::lj::LUA_NOREF,
                period,
                oneshot,
                bt_next: boottime_ms().wrapping_add(period),
                n,
                fires: 0,
            },
        );
        // INFALLIBLE: just inserted
        self.0.get_mut(name).expect("inserted")
    }
    pub fn del(&mut self, name: &str) {
        self.0.shift_remove(name);
    }
    pub fn next(&self) -> u64 {
        if self.0.is_empty() {
            return 0;
        }
        self.0
            .values()
            .map(|t| t.bt_next)
            .min()
            .unwrap_or(0x7FFFFFFFFFFFFFFF)
            .min(0x7FFFFFFFFFFFFFFF)
    }
}

/// TimerPoolNext with the dirty flag reset.
pub fn timer_pool_next() -> u64 {
    let p = params();
    p.timers_dirty.set(false);

    p.timers.borrow().next()
}

/// TimerPoolRun: fire due timers. Lua callbacks may add/delete timers (they set timers_dirty).
pub fn timer_pool_run(bt: u64) -> u64 {
    let p = params();
    if p.timers.borrow().is_empty() {
        p.timers_dirty.set(false);
        return 0;
    }
    let bt = if bt == 0 { boottime_ms() } else { bt };
    'again: loop {
        let mut mintime: u64 = 0x7FFFFFFFFFFFFFFF;
        p.timers_dirty.set(false);
        let mut i = 0;
        loop {
            let snapshot = {
                let t = p.timers.borrow();
                match t.0.get_index(i) {
                    None => break,
                    Some((name, e)) => (
                        name.clone(),
                        e.bt_next,
                        e.n,
                        e.func_ref,
                        e.lua_ref,
                        e.period,
                        e.oneshot,
                    ),
                }
            };
            let (name, bt_next, n, func, data, period, oneshot) = snapshot;
            let mut alive = true;
            if bt >= bt_next {
                let fires = {
                    let mut t = p.timers.borrow_mut();
                    // INFALLIBLE: index valid, just read
                    let e = t.0.get_index_mut(i).expect("timer").1;
                    e.fires += 1;
                    e.fires
                };
                dlog!(
                    "\ntimer: '{}' period {} oneshot {} fires={}\n",
                    name,
                    period,
                    oneshot as u8,
                    fires
                );
                let ok = crate::lua::call_timer(func, &name, data);
                let mut del: Option<&str> = if ok {
                    None
                } else {
                    Some("timer: '{}' deleted because of error\n")
                };
                let dirty = p.timers_dirty.get();
                let mut t = p.timers.borrow_mut();
                let idx = if dirty {
                    match t.0.get_full(&name) {
                        Some((j, _, e)) if e.n == n => Some(j),
                        _ => None,
                    }
                } else {
                    Some(i)
                };
                match idx {
                    Some(j) => {
                        if del.is_none() && t.0[j].oneshot {
                            del = Some("timer: '{}' deleted because of oneshot\n");
                        }
                        if let Some(msg) = del {
                            dlog!("{}", msg.replace("{}", &name));
                            t.0.shift_remove_index(j);
                            alive = false;
                        } else {
                            t.0[j].bt_next = bt.wrapping_add(t.0[j].period);
                        }
                    }
                    None => alive = false,
                }
                if dirty {
                    continue 'again;
                }
                if alive {
                    mintime = mintime.min(t.0[i].bt_next);
                }
            } else {
                mintime = mintime.min(bt_next);
            }
            if alive {
                i += 1;
            }
        }
        if p.timers.borrow().is_empty() {
            return 0;
        }
        return mintime;
    }
}
