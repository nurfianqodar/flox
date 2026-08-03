const std = @import("std");
const proc = std.process;
const utils = @import("../utils.zig");
const crypto = std.crypto;
const mem = std.mem;
const flox = @import("../../flox.zig");

const Console = @import("../Console.zig");

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

pub fn run(
    options: *const EncryptOptions,
    io: std.Io,
    allocator: std.mem.Allocator,
    env_map: *proc.Environ.Map,
    console: *Console,
) !void {
    var cwd = std.Io.Dir.cwd();

    const ipath = options.input orelse return error.ArgumentNotEnough;
    if (try flox.isFloxFile(io, ipath)) return error.AlreadyEncrypted;
    var ifile = try cwd.openFile(io, ipath, .{ .mode = .read_only });
    defer ifile.close(io);

    const opath = options.output orelse ipath;
    if (try flox.isFileExists(io, opath) and !options.force) return error.PathAlreadyExists;
    var aofile = try cwd.createFileAtomic(io, opath, .{ .replace = true });
    defer aofile.deinit(io);

    const meta: flox.Cipher.Metadata = try .init(io, .{
        // cipher meta accept in KiB while options in MiB
        .m = @intFromFloat(options.m * 1024.0),
        .t = options.t,
        .p = options.p,
    });

    var password_buf: [utils.max_password_length]u8 = undefined;
    defer crypto.secureZero(u8, &password_buf);
    const password = try options.getPassword(env_map, &password_buf, console);

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
