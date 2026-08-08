const std = @import("std");
const mem = std.mem;
const proc = std.process;
const fmt = std.fmt;

const environ_password_key: []const u8 = "FLOX_PASSWORD";
pub const max_password_length: comptime_int = 1024;

/// check is cli flag equal
pub fn eqlFlag(s: []const u8, long: []const u8, short: []const u8) bool {
    return mem.eql(u8, s, long) or mem.eql(u8, s, short);
}

/// get required string from `Args.Iterator`
/// return error.ValueRequired if next is null
pub fn nextString(iter: *proc.Args.Iterator) ![]const u8 {
    const v = iter.next() orelse return error.ValueRequired;
    return v;
}

/// get required interger from `Args.Iterator`
/// return error.ValueRequired if next is null
pub fn nextInt(comptime T: type, iter: *proc.Args.Iterator) !T {
    const v = iter.next() orelse return error.ValueRequired;
    const i = try fmt.parseInt(T, v, 10);
    return i;
}

/// get required float from `Args.Iterator`
/// return error.ValueRequired if next is null
pub fn nextFloat(comptime T: type, iter: *proc.Args.Iterator) !T {
    const v = iter.next() orelse return error.ValueRequired;
    const i = try fmt.parseFloat(T, v);
    return i;
}

/// get password from `FLOX_PASSWORD` environment variable
pub fn getEnvPassword(env_map: *proc.Environ.Map, buf: []u8) ![]const u8 {
    const pwd = env_map.get(environ_password_key) orelse
        return error.PasswordNotProvided;
    if (pwd.len > buf.len) return error.PasswordTooLong;
    @memcpy(buf[0..pwd.len], pwd);
    return buf[0..pwd.len];
}
