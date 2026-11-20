//! Thin layer over the raw LuaJIT (Lua 5.1) C API from mlua-sys.
//! Only raw symbols are used (the `_`-suffixed ones), never mlua-sys' 5.3 compat emulation,
//! so behavior matches the C original that links the same library (ADR-008).
//!
//! SAFETY (module-wide): every function takes a `*mut lua_State` that must be a live state
//! owned by this process; callers follow the Lua stack discipline of the C original.

#![allow(non_snake_case)]

use mlua::ffi;
pub use mlua::ffi::{
    lua_CFunction, lua_Debug, lua_Integer, lua_State, LUA_GCCOLLECT, LUA_GCCOUNT, LUA_GLOBALSINDEX,
    LUA_MASKCALL, LUA_MASKCOUNT, LUA_MASKLINE, LUA_MASKRET, LUA_MULTRET, LUA_NOREF,
    LUA_REGISTRYINDEX, LUA_TBOOLEAN, LUA_TFUNCTION, LUA_TNIL, LUA_TNUMBER, LUA_TSTRING, LUA_TTABLE,
};
use std::os::raw::{c_char, c_int, c_void};

pub type L = *mut lua_State;

#[inline]
pub unsafe fn gettop(l: L) -> c_int {
    ffi::lua_gettop(l)
}
#[inline]
pub unsafe fn settop(l: L, n: c_int) {
    ffi::lua_settop(l, n)
}
#[inline]
pub unsafe fn pop(l: L, n: c_int) {
    ffi::lua_settop(l, -n - 1)
}
#[inline]
pub unsafe fn typ(l: L, i: c_int) -> c_int {
    ffi::lua_type(l, i)
}
#[inline]
pub unsafe fn isnil(l: L, i: c_int) -> bool {
    typ(l, i) == LUA_TNIL
}
#[inline]
pub unsafe fn isnoneornil(l: L, i: c_int) -> bool {
    typ(l, i) <= 0
}
#[inline]
pub unsafe fn istable(l: L, i: c_int) -> bool {
    typ(l, i) == LUA_TTABLE
}
#[inline]
pub unsafe fn isfunction(l: L, i: c_int) -> bool {
    typ(l, i) == LUA_TFUNCTION
}
#[inline]
pub unsafe fn isstring(l: L, i: c_int) -> bool {
    ffi::lua_isstring(l, i) != 0
}
#[inline]
pub unsafe fn pushnil(l: L) {
    ffi::lua_pushnil(l)
}
#[inline]
pub unsafe fn pushboolean(l: L, b: bool) {
    ffi::lua_pushboolean(l, b as c_int)
}
#[inline]
pub unsafe fn pushinteger(l: L, v: i64) {
    ffi::lua_pushinteger(l, v as lua_Integer)
}
#[inline]
pub unsafe fn pushnumber(l: L, v: f64) {
    ffi::lua_pushnumber(l, v)
}
#[inline]
pub unsafe fn pushbytes(l: L, b: &[u8]) {
    ffi::lua_pushlstring_(l, b.as_ptr() as *const c_char, b.len());
}
#[inline]
pub unsafe fn pushstr(l: L, s: &str) {
    pushbytes(l, s.as_bytes())
}
#[inline]
pub unsafe fn pushvalue(l: L, i: c_int) {
    ffi::lua_pushvalue(l, i)
}
#[inline]
pub unsafe fn remove(l: L, i: c_int) {
    ffi::lua_remove(l, i)
}
#[inline]
pub unsafe fn newtable(l: L) {
    ffi::lua_createtable(l, 0, 0)
}
#[inline]
pub unsafe fn createtable(l: L, narr: c_int, nrec: c_int) {
    ffi::lua_createtable(l, narr, nrec)
}
#[inline]
pub unsafe fn rawset(l: L, i: c_int) {
    ffi::lua_rawset(l, i)
}
#[inline]
pub unsafe fn rawgeti(l: L, i: c_int, n: i64) {
    ffi::lua_rawgeti_(l, i, n as c_int)
}
pub unsafe fn getfield(l: L, i: c_int, k: &str) {
    let c = cstr(k);
    ffi::lua_getfield_(l, i, c.as_ptr());
}
pub unsafe fn setfield(l: L, i: c_int, k: &str) {
    let c = cstr(k);
    ffi::lua_setfield(l, i, c.as_ptr());
}
pub unsafe fn getglobal(l: L, k: &str) {
    getfield(l, LUA_GLOBALSINDEX, k)
}
pub unsafe fn setglobal(l: L, k: &str) {
    setfield(l, LUA_GLOBALSINDEX, k)
}
#[inline]
pub unsafe fn toboolean(l: L, i: c_int) -> bool {
    ffi::lua_toboolean(l, i) != 0
}
#[inline]
pub unsafe fn tointeger(l: L, i: c_int) -> i64 {
    ffi::lua_tointeger_(l, i) as i64
}
/// lua_tolstring: None when not convertible. Converts numbers in place like C.
pub unsafe fn tobytes<'a>(l: L, i: c_int) -> Option<&'a [u8]> {
    let mut len = 0usize;
    let p = ffi::lua_tolstring(l, i, &mut len);
    if p.is_null() {
        None
    } else {
        Some(std::slice::from_raw_parts(p as *const u8, len))
    }
}
#[inline]
pub unsafe fn rawlen(l: L, i: c_int) -> usize {
    ffi::lua_objlen(l, i)
}
#[inline]
pub unsafe fn newuserdata(l: L, sz: usize) -> *mut c_void {
    ffi::lua_newuserdata(l, sz)
}
#[inline]
pub unsafe fn absindex(l: L, i: c_int) -> c_int {
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
pub unsafe fn error(l: L, msg: &str) -> ! {
    let c = std::ffi::CString::new(msg.replace('\0', "")).unwrap_or_default();
    ffi::luaL_error(l, c"%s".as_ptr(), c.as_ptr());
    // INFALLIBLE: luaL_error never returns
    unreachable!()
}

pub unsafe fn checkinteger(l: L, i: c_int) -> i64 {
    ffi::luaL_checkinteger(l, i) as i64
}
pub unsafe fn checklstring<'a>(l: L, i: c_int) -> &'a [u8] {
    let mut len = 0usize;
    let p = ffi::luaL_checklstring(l, i, &mut len);
    std::slice::from_raw_parts(p as *const u8, len)
}
pub unsafe fn checkstring<'a>(l: L, i: c_int) -> &'a [u8] {
    checklstring(l, i)
}
pub unsafe fn checktype(l: L, i: c_int, t: c_int) {
    ffi::luaL_checktype(l, i, t)
}
pub unsafe fn checkudata(l: L, i: c_int, tname: &std::ffi::CStr) -> *mut c_void {
    ffi::luaL_checkudata(l, i, tname.as_ptr())
}
pub unsafe fn newmetatable(l: L, tname: &std::ffi::CStr) -> c_int {
    ffi::luaL_newmetatable_(l, tname.as_ptr())
}
pub unsafe fn getmetatable_reg(l: L, tname: &std::ffi::CStr) {
    ffi::lua_getfield_(l, LUA_REGISTRYINDEX, tname.as_ptr());
}
pub unsafe fn setmetatable(l: L, i: c_int) {
    ffi::lua_setmetatable(l, i);
}
pub unsafe fn ref_(l: L) -> c_int {
    ffi::luaL_ref(l, LUA_REGISTRYINDEX)
}
pub unsafe fn unref(l: L, r: c_int) {
    ffi::luaL_unref(l, LUA_REGISTRYINDEX, r)
}
pub unsafe fn register(l: L, name: &str, f: lua_CFunction) {
    ffi::lua_pushcclosure(l, f, 0);
    setglobal(l, name);
}
pub unsafe fn pushcfunction(l: L, f: lua_CFunction) {
    ffi::lua_pushcclosure(l, f, 0);
}
pub unsafe fn pcall(l: L, nargs: c_int, nres: c_int) -> c_int {
    ffi::lua_pcall(l, nargs, nres, 0)
}
pub unsafe fn call(l: L, nargs: c_int, nres: c_int) {
    ffi::lua_call(l, nargs, nres)
}
pub unsafe fn loadbuffer(l: L, b: &[u8], name: &str) -> c_int {
    let n = cstr(name);
    ffi::luaL_loadbuffer(l, b.as_ptr() as *const c_char, b.len(), n.as_ptr())
}
pub unsafe fn dostring(l: L, s: &[u8]) -> c_int {
    let c = std::ffi::CString::new(s.to_vec()).unwrap_or_default();
    let r = ffi::luaL_loadstring(l, c.as_ptr());
    if r != 0 {
        return r;
    }
    pcall(l, 0, LUA_MULTRET)
}
pub unsafe fn dofile(l: L, f: &str) -> c_int {
    let c = cstr(f);
    let r = ffi::luaL_loadfile(l, c.as_ptr());
    if r != 0 {
        return r;
    }
    pcall(l, 0, LUA_MULTRET)
}
pub unsafe fn newstate() -> L {
    ffi::luaL_newstate()
}
pub unsafe fn openlibs(l: L) {
    ffi::luaL_openlibs(l)
}
pub unsafe fn close(l: L) {
    ffi::lua_close(l)
}
pub unsafe fn atpanic(l: L, f: lua_CFunction) {
    ffi::lua_atpanic(l, f);
}
pub unsafe fn gc(l: L, what: c_int, data: c_int) -> c_int {
    ffi::lua_gc(l, what, data)
}
pub unsafe fn sethook(
    l: L,
    f: Option<unsafe extern "C-unwind" fn(L, *mut lua_Debug)>,
    mask: c_int,
    count: c_int,
) {
    ffi::lua_sethook(l, f, mask, count);
}
