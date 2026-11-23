//! Safe layer over the raw LuaJIT (Lua 5.1) C API from mlua-sys. This module holds the Lua
//! bindings' `unsafe`; everything above it is safe Rust.
//!
//! Only raw symbols are used (the `_`-suffixed ones), never mlua-sys' 5.3 compat emulation,
//! so behavior matches the C original that links the same library (ADR-008).
//!
//! Soundness rules enforced here instead of trusting callers (LuaJIT builds without API
//! checks, so a bad index or a missing stack slot is undefined behavior there):
//! - every stack index is validated; an invalid one raises a Lua error;
//! - every push first makes sure the stack has room (`lua_checkstack`): it only grows the
//!   stack when the C original would have overflowed it, so memory use stays identical;
//! - operations that need a table at an index check its type;
//! - strings are returned as owned copies, never as references into the Lua stack.
//!
//! An `L` is only created from a state LuaJIT hands to a C function (`cfn!`), or from
//! `newstate`; it must not be used after `close` (which is `unsafe` for that reason).

use mlua::ffi;
pub use mlua::ffi::{
    lua_CFunction, lua_Debug, lua_Integer, lua_State, LUA_GCCOLLECT, LUA_GCCOUNT, LUA_GLOBALSINDEX,
    LUA_MASKCALL, LUA_MASKCOUNT, LUA_MASKLINE, LUA_MASKRET, LUA_MULTRET, LUA_NOREF,
    LUA_REGISTRYINDEX, LUA_TBOOLEAN, LUA_TFUNCTION, LUA_TNIL, LUA_TNUMBER, LUA_TSTRING, LUA_TTABLE,
};
use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_void};
use std::ptr::NonNull;

const LUA_ENVIRONINDEX: c_int = -10001;

/// A live LuaJIT state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct L(NonNull<lua_State>);

impl L {
    /// # Safety
    /// `p` must be a live `lua_State` that stays alive while the returned value is used.
    pub unsafe fn from_raw(p: *mut lua_State) -> Option<L> {
        NonNull::new(p).map(L)
    }
    pub fn as_ptr(self) -> *mut lua_State {
        self.0.as_ptr()
    }
}

/// Wrap a safe `fn(L) -> c_int` as a `lua_CFunction`.
#[macro_export]
macro_rules! cfn {
    ($f:path) => {{
        unsafe extern "C-unwind" fn trampoline(
            p: *mut $crate::lua::lj::lua_State,
        ) -> std::os::raw::c_int {
            // SAFETY: LuaJIT calls a C function with its live, non-null state.
            match unsafe { $crate::lua::lj::L::from_raw(p) } {
                Some(l) => $f(l),
                None => 0,
            }
        }
        trampoline as $crate::lua::lj::lua_CFunction
    }};
}

// ---- checks ----

fn is_pseudo(i: c_int) -> bool {
    i == LUA_REGISTRYINDEX || i == LUA_GLOBALSINDEX || i == LUA_ENVIRONINDEX
}

/// Index of an existing stack slot or a pseudo index.
fn slot(l: L, i: c_int) {
    let top = gettop(l);
    let ok = is_pseudo(i) || (i > 0 && i <= top) || (i < 0 && i > LUA_REGISTRYINDEX && -i <= top);
    if !ok {
        error(l, "invalid stack index");
    }
}

/// Index for reading: positive indices above the top are "none", which LuaJIT handles.
fn readable(l: L, i: c_int) {
    if i < 0 && !is_pseudo(i) && (i <= LUA_REGISTRYINDEX || -i > gettop(l)) {
        error(l, "invalid stack index");
    }
}

fn need_top(l: L, n: c_int) {
    if gettop(l) < n {
        error(l, "stack underflow");
    }
}

fn room(l: L, n: c_int) {
    // SAFETY: live state; lua_checkstack only grows the stack.
    if unsafe { ffi::lua_checkstack(l.as_ptr(), n) } == 0 {
        error(l, "stack overflow");
    }
}

fn table_at(l: L, i: c_int) {
    slot(l, i);
    if typ(l, i) != LUA_TTABLE {
        error(l, "table expected");
    }
}

// ---- stack ----

pub fn gettop(l: L) -> c_int {
    // SAFETY: live state.
    unsafe { ffi::lua_gettop(l.as_ptr()) }
}
pub fn settop(l: L, n: c_int) {
    let top = gettop(l);
    if n >= 0 {
        if n > top {
            room(l, n - top);
        }
    } else if -(n + 1) > top {
        error(l, "invalid stack index");
    }
    // SAFETY: n is within the stack (checked above).
    unsafe { ffi::lua_settop(l.as_ptr(), n) }
}
pub fn pop(l: L, n: c_int) {
    settop(l, -n - 1)
}
pub fn typ(l: L, i: c_int) -> c_int {
    readable(l, i);
    // SAFETY: index checked.
    unsafe { ffi::lua_type(l.as_ptr(), i) }
}
pub fn isnil(l: L, i: c_int) -> bool {
    typ(l, i) == LUA_TNIL
}
pub fn isnoneornil(l: L, i: c_int) -> bool {
    typ(l, i) <= 0
}
pub fn istable(l: L, i: c_int) -> bool {
    typ(l, i) == LUA_TTABLE
}
pub fn isfunction(l: L, i: c_int) -> bool {
    typ(l, i) == LUA_TFUNCTION
}
pub fn isstring(l: L, i: c_int) -> bool {
    readable(l, i);
    // SAFETY: index checked.
    unsafe { ffi::lua_isstring(l.as_ptr(), i) != 0 }
}
pub fn isnumber(l: L, i: c_int) -> bool {
    readable(l, i);
    // SAFETY: index checked.
    unsafe { ffi::lua_isnumber(l.as_ptr(), i) != 0 }
}
pub fn pushnil(l: L) {
    room(l, 1);
    // SAFETY: room checked.
    unsafe { ffi::lua_pushnil(l.as_ptr()) }
}
pub fn pushboolean(l: L, b: bool) {
    room(l, 1);
    // SAFETY: room checked.
    unsafe { ffi::lua_pushboolean(l.as_ptr(), b as c_int) }
}
pub fn pushinteger(l: L, v: i64) {
    room(l, 1);
    // SAFETY: room checked.
    unsafe { ffi::lua_pushinteger(l.as_ptr(), v as ffi::lua_Integer) }
}
pub fn pushnumber(l: L, v: f64) {
    room(l, 1);
    // SAFETY: room checked.
    unsafe { ffi::lua_pushnumber(l.as_ptr(), v) }
}
pub fn pushbytes(l: L, b: &[u8]) {
    room(l, 1);
    // SAFETY: room checked; Lua copies the bytes.
    unsafe {
        ffi::lua_pushlstring_(l.as_ptr(), b.as_ptr() as *const c_char, b.len());
    }
}
pub fn pushstr(l: L, s: &str) {
    pushbytes(l, s.as_bytes())
}
pub fn pushvalue(l: L, i: c_int) {
    slot(l, i);
    room(l, 1);
    // SAFETY: index and room checked.
    unsafe { ffi::lua_pushvalue(l.as_ptr(), i) }
}
pub fn remove(l: L, i: c_int) {
    slot(l, i);
    if is_pseudo(i) {
        error(l, "invalid stack index");
    }
    // SAFETY: real stack slot.
    unsafe { ffi::lua_remove(l.as_ptr(), i) }
}
pub fn newtable(l: L) {
    createtable(l, 0, 0)
}
pub fn createtable(l: L, narr: c_int, nrec: c_int) {
    room(l, 1);
    // SAFETY: room checked.
    unsafe { ffi::lua_createtable(l.as_ptr(), narr, nrec) }
}
pub fn rawset(l: L, i: c_int) {
    need_top(l, 2);
    table_at(l, i);
    // SAFETY: table at i, key and value on top.
    unsafe { ffi::lua_rawset(l.as_ptr(), i) }
}
pub fn rawgeti(l: L, i: c_int, n: i64) {
    table_at(l, i);
    room(l, 1);
    // SAFETY: table at i, room checked.
    unsafe { ffi::lua_rawgeti_(l.as_ptr(), i, n as c_int) }
}
pub fn getfield(l: L, i: c_int, k: &str) {
    slot(l, i);
    room(l, 1);
    let c = cstr(k);
    // SAFETY: index and room checked; a non-table raises a regular Lua error.
    unsafe { ffi::lua_getfield_(l.as_ptr(), i, c.as_ptr()) }
}
pub fn setfield(l: L, i: c_int, k: &str) {
    need_top(l, 1);
    slot(l, i);
    let c = cstr(k);
    // SAFETY: index checked, value on top.
    unsafe { ffi::lua_setfield(l.as_ptr(), i, c.as_ptr()) }
}
pub fn getglobal(l: L, k: &str) {
    getfield(l, LUA_GLOBALSINDEX, k)
}
pub fn setglobal(l: L, k: &str) {
    setfield(l, LUA_GLOBALSINDEX, k)
}
pub fn toboolean(l: L, i: c_int) -> bool {
    readable(l, i);
    // SAFETY: index checked.
    unsafe { ffi::lua_toboolean(l.as_ptr(), i) != 0 }
}
pub fn tointeger(l: L, i: c_int) -> i64 {
    readable(l, i);
    // SAFETY: index checked.
    unsafe { ffi::lua_tointeger_(l.as_ptr(), i) as i64 }
}
/// lua_tolstring (converts numbers in place like C). None when not convertible.
pub fn tobytes(l: L, i: c_int) -> Option<Vec<u8>> {
    readable(l, i);
    let mut len = 0usize;
    // SAFETY: index checked; the bytes are copied before anything else touches the stack.
    unsafe {
        let p = ffi::lua_tolstring(l.as_ptr(), i, &mut len);
        (!p.is_null()).then(|| std::slice::from_raw_parts(p as *const u8, len).to_vec())
    }
}
pub fn rawlen(l: L, i: c_int) -> usize {
    readable(l, i);
    // SAFETY: index checked.
    unsafe { ffi::lua_objlen(l.as_ptr(), i) }
}
/// New full userdata of `sz` bytes on the stack. The pointer stays valid while the
/// userdata is referenced (LuaJIT's GC does not move objects).
pub fn newuserdata(l: L, sz: usize) -> *mut c_void {
    room(l, 1);
    // SAFETY: room checked.
    unsafe { ffi::lua_newuserdata(l.as_ptr(), sz) }
}
/// Zero-filled full userdata of `sz` bytes whose first word stores `id` (handle into a
/// Rust-side table). Same Lua heap footprint as a C struct of that size.
pub fn newuserdata_id(l: L, sz: usize, id: usize) {
    let sz = sz.max(std::mem::size_of::<usize>());
    let p = newuserdata(l, sz) as *mut u8;
    // SAFETY: p points to a fresh block of sz bytes, sz >= size_of::<usize>().
    unsafe {
        std::ptr::write_bytes(p, 0, sz);
        std::ptr::write_unaligned(p as *mut usize, id);
    }
}
/// The id of a `newuserdata_id` userdata with metatable `tname` at `i` (raises otherwise).
pub fn checkudata_id(l: L, i: c_int, tname: &CStr) -> usize {
    let p = checkudata(l, i, tname);
    // SAFETY: userdata with this metatable are only made by newuserdata_id.
    unsafe { std::ptr::read_unaligned(p as *const usize) }
}
pub fn absindex(l: L, i: c_int) -> c_int {
    if i < 0 && i > LUA_REGISTRYINDEX {
        gettop(l) + i + 1
    } else {
        i
    }
}

pub fn cstr(s: &str) -> std::ffi::CString {
    std::ffi::CString::new(s.replace('\0', "")).unwrap_or_default()
}

/// luaL_error(L, "%s", msg): LuaJIT adds the location of the calling Lua function.
pub fn error(l: L, msg: &str) -> ! {
    let c = cstr(msg);
    // SAFETY: live state; luaL_error unwinds to the enclosing protected call.
    unsafe {
        ffi::luaL_error(l.as_ptr(), c"%s".as_ptr(), c.as_ptr());
    }
    // INFALLIBLE: luaL_error never returns
    unreachable!()
}

// luaL_error builds the message in LuaJIT's temporary buffer, which is part of the Lua
// heap; `%d`/`%u` reserve extra room there. The messages the C original formats with
// numbers are therefore raised with the same format string and arguments (ADR-009).

/// luaL_error(L, "%s expect exactly %d arguments, got %d", ...)
pub fn error_argc(l: L, where_: &str, expect: c_int, got: c_int) -> ! {
    let w = cstr(where_);
    // SAFETY: the format's conversions match the argument types.
    unsafe {
        ffi::luaL_error(
            l.as_ptr(),
            c"%s expect exactly %d arguments, got %d".as_ptr(),
            w.as_ptr(),
            expect,
            got,
        );
    }
    // INFALLIBLE: luaL_error never returns
    unreachable!()
}
/// luaL_error(L, "%s expect from %d to %d arguments, got %d", ...)
pub fn error_argc_range(l: L, where_: &str, min: c_int, max: c_int, got: c_int) -> ! {
    let w = cstr(where_);
    // SAFETY: the format's conversions match the argument types.
    unsafe {
        ffi::luaL_error(
            l.as_ptr(),
            c"%s expect from %d to %d arguments, got %d".as_ptr(),
            w.as_ptr(),
            min,
            max,
            got,
        );
    }
    // INFALLIBLE: luaL_error never returns
    unreachable!()
}
/// luaL_error(L, fmt, v) for a format with exactly one `%u` and no other conversion
/// (checked; anything else is raised as a plain message).
pub fn error_u(l: L, fmt: &CStr, v: u32) -> ! {
    let b = fmt.to_bytes();
    let ok = b.iter().filter(|&&c| c == b'%').count() == 1 && b.windows(2).any(|w| w == b"%u");
    if !ok {
        error(l, &fmt.to_string_lossy());
    }
    // SAFETY: fmt has exactly one conversion, %u, matching the unsigned argument.
    unsafe {
        ffi::luaL_error(l.as_ptr(), fmt.as_ptr(), v as std::os::raw::c_uint);
    }
    // INFALLIBLE: luaL_error never returns
    unreachable!()
}

// lua.h's *lint macros: 64-bit values travel as lua_Integer where that is 64-bit, and as
// lua_Number (double) on 32-bit targets, where LuaJIT's lua_Integer is 32-bit.
const LINT_IS_NUMBER: bool = std::mem::size_of::<ffi::lua_Integer>() < 8;

/// lua_pushlint
pub fn pushlint(l: L, v: i64) {
    if LINT_IS_NUMBER {
        pushnumber(l, v as f64)
    } else {
        pushinteger(l, v)
    }
}
/// luaL_checklint
pub fn checklint(l: L, i: c_int) -> i64 {
    readable(l, i);
    if LINT_IS_NUMBER {
        // SAFETY: index checked; raises a Lua error on a wrong type.
        unsafe { ffi::luaL_checknumber(l.as_ptr(), i) as i64 }
    } else {
        checkinteger(l, i)
    }
}
/// lua_tolint
pub fn tolint(l: L, i: c_int) -> i64 {
    readable(l, i);
    if LINT_IS_NUMBER {
        // SAFETY: index checked.
        unsafe { ffi::lua_tonumber(l.as_ptr(), i) as i64 }
    } else {
        tointeger(l, i)
    }
}

pub fn checkinteger(l: L, i: c_int) -> i64 {
    readable(l, i);
    // SAFETY: index checked; raises a Lua error on a wrong type.
    unsafe { ffi::luaL_checkinteger(l.as_ptr(), i) as i64 }
}
pub fn checklstring(l: L, i: c_int) -> Vec<u8> {
    readable(l, i);
    let mut len = 0usize;
    // SAFETY: index checked; never returns NULL (raises instead); bytes copied at once.
    unsafe {
        let p = ffi::luaL_checklstring(l.as_ptr(), i, &mut len);
        std::slice::from_raw_parts(p as *const u8, len).to_vec()
    }
}
pub fn checkstring(l: L, i: c_int) -> Vec<u8> {
    checklstring(l, i)
}
pub fn checktype(l: L, i: c_int, t: c_int) {
    readable(l, i);
    // SAFETY: index checked.
    unsafe { ffi::luaL_checktype(l.as_ptr(), i, t) }
}
/// Pointer to the userdata block of metatable `tname` at `i` (raises otherwise).
pub fn checkudata(l: L, i: c_int, tname: &CStr) -> *mut c_void {
    readable(l, i);
    // SAFETY: index checked.
    unsafe { ffi::luaL_checkudata(l.as_ptr(), i, tname.as_ptr()) }
}
pub fn newmetatable(l: L, tname: &CStr) -> c_int {
    room(l, 2);
    // SAFETY: room checked.
    unsafe { ffi::luaL_newmetatable_(l.as_ptr(), tname.as_ptr()) }
}
pub fn getmetatable_reg(l: L, tname: &CStr) {
    room(l, 1);
    // SAFETY: room checked.
    unsafe { ffi::lua_getfield_(l.as_ptr(), LUA_REGISTRYINDEX, tname.as_ptr()) }
}
pub fn setmetatable(l: L, i: c_int) {
    need_top(l, 1);
    slot(l, i);
    let t = typ(l, -1);
    if t != LUA_TTABLE && t != LUA_TNIL {
        error(l, "table expected");
    }
    // SAFETY: index checked, table or nil on top.
    unsafe {
        ffi::lua_setmetatable(l.as_ptr(), i);
    }
}
pub fn ref_(l: L) -> c_int {
    need_top(l, 1);
    // SAFETY: value on top.
    unsafe { ffi::luaL_ref(l.as_ptr(), LUA_REGISTRYINDEX) }
}
pub fn unref(l: L, r: c_int) {
    // SAFETY: luaL_unref ignores LUA_NOREF/LUA_REFNIL.
    unsafe { ffi::luaL_unref(l.as_ptr(), LUA_REGISTRYINDEX, r) }
}
pub fn pushcfunction(l: L, f: lua_CFunction) {
    room(l, 1);
    // SAFETY: room checked.
    unsafe { ffi::lua_pushcclosure(l.as_ptr(), f, 0) }
}
pub fn register(l: L, name: &str, f: lua_CFunction) {
    pushcfunction(l, f);
    setglobal(l, name);
}
pub fn pcall(l: L, nargs: c_int, nres: c_int) -> c_int {
    need_top(l, nargs + 1);
    // SAFETY: function and arguments on the stack.
    unsafe { ffi::lua_pcall(l.as_ptr(), nargs, nres, 0) }
}
pub fn call(l: L, nargs: c_int, nres: c_int) {
    need_top(l, nargs + 1);
    // SAFETY: function and arguments on the stack; errors propagate as Lua errors.
    unsafe { ffi::lua_call(l.as_ptr(), nargs, nres) }
}
pub fn loadbuffer(l: L, b: &[u8], name: &str) -> c_int {
    room(l, 1);
    let n = cstr(name);
    // SAFETY: room checked; buffer valid for its length.
    unsafe { ffi::luaL_loadbuffer(l.as_ptr(), b.as_ptr() as *const c_char, b.len(), n.as_ptr()) }
}
pub fn dostring(l: L, s: &[u8]) -> c_int {
    room(l, 1);
    let c = std::ffi::CString::new(s.to_vec()).unwrap_or_default();
    // SAFETY: room checked; NUL-terminated chunk.
    let r = unsafe { ffi::luaL_loadstring(l.as_ptr(), c.as_ptr()) };
    if r != 0 {
        return r;
    }
    pcall(l, 0, LUA_MULTRET)
}
pub fn dofile(l: L, f: &str) -> c_int {
    room(l, 1);
    let c = cstr(f);
    // SAFETY: room checked; NUL-terminated file name.
    let r = unsafe { ffi::luaL_loadfile(l.as_ptr(), c.as_ptr()) };
    if r != 0 {
        return r;
    }
    pcall(l, 0, LUA_MULTRET)
}
pub fn newstate() -> Option<L> {
    // SAFETY: a fresh state, owned by the caller until `close`.
    unsafe { L::from_raw(ffi::luaL_newstate()) }
}
pub fn openlibs(l: L) {
    // SAFETY: live state.
    unsafe { ffi::luaL_openlibs(l.as_ptr()) }
}
/// # Safety
/// `l` and every copy of it must not be used afterwards.
pub unsafe fn close(l: L) {
    ffi::lua_close(l.as_ptr())
}
pub fn atpanic(l: L, f: lua_CFunction) {
    // SAFETY: live state.
    unsafe {
        ffi::lua_atpanic(l.as_ptr(), f);
    }
}
pub fn gc(l: L, what: c_int, data: c_int) -> c_int {
    // SAFETY: live state.
    unsafe { ffi::lua_gc(l.as_ptr(), what, data) }
}
pub type Hook = unsafe extern "C-unwind" fn(*mut lua_State, *mut lua_Debug);
pub fn sethook(l: L, f: Option<Hook>, mask: c_int, count: c_int) {
    // SAFETY: live state; a hook is a plain function pointer.
    unsafe {
        ffi::lua_sethook(l.as_ptr(), f, mask, count);
    }
}
