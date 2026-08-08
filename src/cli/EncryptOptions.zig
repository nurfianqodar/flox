const builtin = @import("builtin");
const std = @import("std");
const proc = std.process;
const crypto = std.crypto;
const mem = std.mem;

const utils = @import("utils.zig");
const flox = @import("../flox.zig");
const Console = @import("Console.zig");

const EncryptOptions = @This();

/// input file is required
input: ?[]const u8 = null,

/// output file is required
output: ?[]const u8 = null,

/// password prompted if ommited
password: ?[]const u8 = null,

/// overwrite output file if exists
force: bool = false,

/// interactive
interactive: bool = false,

/// argon2id memory cost in MiB
m: f32 = 64,

/// argon2id time cost
t: u32 = 1,

/// argon2id parallelism
p: u24 = 1,

/// chunk size in MiB
chunk_size: f32 = 0.5,

/// parse argument iterator after exe path and command
/// consumed
pub fn parse(iter: *proc.Args.Iterator) !EncryptOptions {
    var options: EncryptOptions = .{};
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
        else if (utils.eqlFlag(arg, "--memory-cost", "-m"))
            options.m = try utils.nextFloat(f32, iter)
        else if (utils.eqlFlag(arg, "--time-cost", "-t"))
            options.t = try utils.nextInt(u32, iter)
        else if (utils.eqlFlag(arg, "--parallelism", "-p"))
            options.p = try utils.nextInt(u24, iter)
        else if (utils.eqlFlag(arg, "--chunk-size", "-c"))
            options.chunk_size = try utils.nextFloat(f32, iter)
        else
            return error.InvalidEncryptOptions;
    }
    return options;
}

/// get password
fn getPassword(
    options: *const EncryptOptions,
    env_map: *proc.Environ.Map,
    buf: []u8,
    console: *Console,
) ![]const u8 {
    // password provided from cli args
    if (options.password) |pwd| {
        if (options.interactive) return error.AmbiguousEncryptOptions;
        if (pwd.len == 0) return error.EmptyPassword;
        if (pwd.len > buf.len) return error.PasswordTooLong;
        @memcpy(buf[0..pwd.len], pwd);
        return buf[0..pwd.len];
    }

    // user ask to interactively input password
    if (options.interactive) {
        var retype_buf: [1024]u8 = undefined;
        defer crypto.secureZero(u8, &retype_buf);

        const pwd = try console.promptPassword("password: ", buf);
        const retype_pwd = try console.promptPassword("retype password: ", &retype_buf);

        if (!mem.eql(u8, pwd, retype_pwd)) return error.PasswordNotMatch;
        return pwd;
    }

    // fallback to environment variable
    return try utils.getEnvPassword(env_map, buf);
}

/// open input file and check is it flox file
fn getInputFile(options: *const EncryptOptions, io: std.Io) !std.Io.File {
    const path = options.input orelse return error.ArgumentNotEnough;
    if (try flox.isFloxFile(io, path)) return error.AlreadyEncrypted;

    var cwd = std.Io.Dir.cwd();
    const file = try cwd.openFile(io, path, .{ .mode = .read_only });
    return file;
}

/// create atomic file for output
fn getOutputFile(options: *const EncryptOptions, io: std.Io) !std.Io.File.Atomic {
    const path = if (options.output) |o| o else if (options.input) |i| i else return error.ArgumentNotEnough;
    if (try flox.isFileExists(io, path) and !options.force) return error.PathAlreadyExists;

    var cwd = std.Io.Dir.cwd();
    const afile = try cwd.createFileAtomic(io, path, .{ .replace = true });
    return afile;
}

/// generate Cipher.Metadata instance
fn getCipherMetadata(options: *const EncryptOptions, io: std.Io) !flox.Cipher.Metadata {
    return try .init(io, .{
        // cipher meta accept in KiB but options in MiB
        // convert before use
        .m = @intFromFloat(options.m * 1024.0),
        .t = options.t,
        .p = options.p,
    });
}

/// run encrypt file
pub fn run(
    options: *const EncryptOptions,
    io: std.Io,
    allocator: std.mem.Allocator,
    env_map: *proc.Environ.Map,
    console: *Console,
) !void {
    if (builtin.mode == .Debug)
        options.debug();

    var ifile = try options.getInputFile(io);
    defer ifile.close(io);

    var aofile = try options.getOutputFile(io);
    defer aofile.deinit(io);

    var password_buf: [utils.max_password_length]u8 = undefined;
    defer crypto.secureZero(u8, &password_buf);
    const password = try options.getPassword(env_map, &password_buf, console);

    const meta = try options.getCipherMetadata(io);

    var cipher: flox.Cipher = try .init(io, allocator, meta, password);
    defer cipher.deinit();

    try flox.encryptStream(
        io,
        allocator,
        &ifile,
        &aofile.file,
        &cipher,
        // encrypt stream receive in bytes while options in MiB
        @intFromFloat(options.chunk_size * 1024.0 * 1024.0),
    );
    try aofile.replace(io);
}

/// debug
fn debug(options: *const EncryptOptions) void {
    std.debug.print(
        \\Input = {s}
        \\Output = {s}
        \\Password = {s}
        \\Interactive = {any}
        \\Force = {any}
        \\Memory cost = {d}
        \\Time cost = {d}
        \\Parallelism = {d}
        \\Chunk size = {d}
        \\
    , .{
        options.input orelse "<empty>",
        options.output orelse "<empty>",
        options.password orelse "<empty>",
        options.interactive,
        options.force,
        options.m,
        options.t,
        options.p,
        options.chunk_size,
    });
}
