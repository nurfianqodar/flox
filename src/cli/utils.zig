const std = @import("std");
const mem = std.mem;
const proc = std.process;
const fmt = std.fmt;

pub const max_password_length: comptime_int = 1024;

pub fn eqlFlag(s: []const u8, long: []const u8, short: []const u8) bool {
    return mem.eql(u8, s, long) or mem.eql(u8, s, short);
}

pub fn nextString(iter: *proc.Args.Iterator) ![]const u8 {
    const v = iter.next() orelse return error.ValueRequired;
    return v;
}

pub fn nextInt(comptime T: type, iter: *proc.Args.Iterator) !T {
    const v = iter.next() orelse return error.ValueRequired;
    const i = try fmt.parseInt(T, v, 10);
    return i;
}

pub fn nextFloat(comptime T: type, iter: *proc.Args.Iterator) !T {
    const v = iter.next() orelse return error.ValueRequired;
    const i = try fmt.parseFloat(T, v);
    return i;
}

const environ_password_key: []const u8 = "FLOX_PASSWORD";

pub fn getEnvPassword(env_map: *proc.Environ.Map, buf: []u8) ![]const u8 {
    const pwd = env_map.get(environ_password_key) orelse
        return error.PasswordNotProvided;
    if (pwd.len > buf.len) return error.PasswordTooLong;
    @memcpy(buf[0..pwd.len], pwd);
    return buf[0..pwd.len];
}
