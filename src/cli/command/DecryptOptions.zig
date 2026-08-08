//! Decrypt file cli options

const builtin = @import("builtin");
const std = @import("std");
const proc = std.process;
const mem = std.mem;

const utils = @import("utils.zig");
const Console = @import("../Console.zig");
const flox = @import("../../flox.zig");

const DecryptOptions = @This();

/// input file path (required)
input: ?[]const u8 = null,

/// output file path (default similar as input file (use force to overwrite))
output: ?[]const u8 = null,

/// encryption password
password: ?[]const u8 = null,

/// ask password interactively
interactive: bool = false,

/// overwrite output file if exists
force: bool = false,

/// parse from arguments
/// iterator should generate new
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

fn getInputFile(options: *const DecryptOptions, io: std.Io) !std.Io.File {
    const path = options.input orelse return error.ArgumentNotEnough;
    if (!try flox.isFloxFile(io, path)) return error.NotEncrypted;
    var cwd = std.Io.Dir.cwd();
    const file = cwd.openFile(io, path, .{ .mode = .read_only });
    return file;
}

fn getOutputFile(options: *const DecryptOptions, io: std.Io) !std.Io.File.Atomic {
    const path = if (options.output) |o| o
        // set input path as output
        else if (options.input) |i| i
        // error
        else return error.ArgumentNotEnough;

    if (try flox.isFileExists(io, path) and !options.force)
        return error.PathAlreadyExists;

    var cwd = std.Io.Dir.cwd();
    const file = try cwd.createFileAtomic(io, path, .{ .replace = true });
    return file;
}

/// get password from stdin
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

/// run decrypt file
pub fn run(
    options: *const DecryptOptions,
    io: std.Io,
    allocator: mem.Allocator,
    env_map: *proc.Environ.Map,
    console: *Console,
) !void {
    if (builtin.mode == .Debug)
        options.debug();

    var ifile = try options.getInputFile(io);
    defer ifile.close(io);

    var ofile = try options.getOutputFile(io);
    defer ofile.deinit(io);

    var password_buf: [utils.max_password_length]u8 = undefined;
    const password = try options.getPassword(env_map, &password_buf, console);

    try flox.decryptStream(io, allocator, &ifile, &ofile.file, password);
    try ofile.replace(io);
}

/// debug
fn debug(options: *const DecryptOptions) void {
    std.debug.print(
        \\Input = {s}
        \\Output = {s}
        \\Password = {s}
        \\Interactive = {any}
        \\Force = {any}
        \\
    , .{
        options.input orelse "<empty>",
        options.output orelse "<empty>",
        options.password orelse "<empty>",
        options.interactive,
        options.force,
    });
}
