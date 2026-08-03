const std = @import("std");
const proc = std.process;
const mem = std.mem;

const utils = @import("utils.zig");
const Console = @import("../Console.zig");
const flox = @import("../../flox.zig");

const DecryptOptions = @This();

input: ?[]const u8 = null,
output: ?[]const u8 = null,
password: ?[]const u8 = null,
interactive: bool = false,
force: bool = false,

pub fn parse(iter: *proc.Args.Iterator) !DecryptOptions {
    var options: DecryptOptions = .{};

    while (iter.next()) |arg| {
        if (utils.eqlFlag(arg, "--input", "-i"))
            options.input = try utils.nextString(iter)
        else if (utils.eqlFlag(arg, "--output", "-o"))
            options.output = try utils.nextString(iter)
        else if (utils.eqlFlag(arg, "--password", "-P"))
            options.password = try utils.nextString(iter)
        else if (utils.eqlFlag(arg, "--force", "-f"))
            options.force = true
        else if (utils.eqlFlag(arg, "--interactive", "-I"))
            options.interactive = true
        else
            return error.InvalidDecryptOptions;
    }
    return options;
}

fn getInputPath(options: *const DecryptOptions) ![]const u8 {
    return options.input orelse return error.ArgumentNotEnough;
}

fn getOutputPath(options: *const DecryptOptions) ![]const u8 {
    if (options.output) |o|
        return o
    else {
        if (options.force)
            return options.input orelse return error.ArgumentNotEnough;
        return error.ArgumentNotEnough;
    }
}

pub fn run(
    options: *const DecryptOptions,
    io: std.Io,
    allocator: mem.Allocator,
    env_map: *proc.Environ.Map,
    console: *Console,
) !void {
    var cwd = std.Io.Dir.cwd();

    const ipath = options.input orelse return error.ArgumentNotEnough;
    if (!try flox.isFloxFile(io, ipath)) return error.NotEncrypted;
    var ifile = try cwd.openFile(io, ipath, .{ .mode = .read_only });
    defer ifile.close(io);

    const opath = options.output orelse ipath;
    if (try flox.isFileExists(io, opath) and !options.force) return error.PathAlreadyExists;
    var ofile = try cwd.createFileAtomic(io, opath, .{ .replace = true });
    defer ofile.deinit(io);

    var password_buf: [utils.max_password_length]u8 = undefined;
    const password = try options.getPassword(env_map, &password_buf, console);

    try flox.decryptStream(io, allocator, &ifile, &ofile.file, password);
    try ofile.replace(io);
}

fn getPassword(
    options: *const DecryptOptions,
    env_map: *proc.Environ.Map,
    buf: []u8,
    console: *Console,
) ![]const u8 {
    if (options.password) |pwd| {
        if (options.interactive) return error.AmbiguousDecryptOptions;
        if (pwd.len == 0) return error.EmptyPassword;
        if (pwd.len > buf.len) return error.PasswordTooLong;
        @memcpy(buf[0..pwd.len], pwd);
        return buf[0..pwd.len];
    }

    if (options.interactive)
        return try console.promptPassword("password: ", buf);

    return try utils.getEnvPassword(env_map, buf);
}
