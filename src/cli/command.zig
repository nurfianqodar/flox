const std = @import("std");
const proc = std.process;
const ascii = std.ascii;
const crypto = std.crypto;
const mem = std.mem;
const fmt = std.fmt;

const flox = @import("../flox.zig");
const Cipher = flox.Cipher;
const Console = @import("Console.zig");
const EncryptOptions = @import("EncryptOptions.zig");
const DecryptOptions = @import("DecryptOptions.zig");

const max_password_length: comptime_int = 1024;
const environ_password_key: []const u8 = "FLOX_PASSWORD";

pub const Command = union(Tag) {
    /// display help message
    help,

    /// display current version
    version,

    /// encrypt a file
    encrypt: EncryptOptions,

    /// decrypt a file
    decrypt: DecryptOptions,

    /// parse cli arguments
    ///
    /// skip first args (exe name) before calling this method
    pub fn parse(args_iter: *proc.Args.Iterator) !Command {
        const tag: Tag = try .parse(args_iter.next() orelse return .help);
        switch (tag) {
            .help => return .help,
            .version => return .version,
            .encrypt => return .{ .encrypt = try .parse(args_iter) },
            .decrypt => return .{ .decrypt = try .parse(args_iter) },
        }
    }

    /// run command
    pub fn run(command: *const Command, io: std.Io, allocator: mem.Allocator, env_map: *proc.Environ.Map) !void {
        var stdin_buffer: [1024 * 4]u8 = undefined;
        defer crypto.secureZero(u8, &stdin_buffer);

        var c: Console = .init(io, null, null, &stdin_buffer);
        defer c.flushAll() catch {};

        switch (command.*) {
            .help => try c.out().print("{s}", .{help_message}),
            .version => try c.out().print("flox {s}\n", .{flox.version_string}),
            .encrypt => |opt| try opt.run(io, allocator, env_map, &c),
            .decrypt => |opt| try opt.run(io, allocator, env_map, &c),
        }
    }

    const Tag = enum {
        help,
        version,
        encrypt,
        decrypt,

        /// parse command from string
        fn parse(s: []const u8) !Tag {
            if (s.len > 7) return error.InvalidCommand;
            var lower_buffer: [7]u8 = undefined;
            const lower = ascii.lowerString(&lower_buffer, s);

            return if (mem.eql(u8, lower, "h") or mem.eql(u8, lower, "help"))
                .help
            else if (mem.eql(u8, lower, "e") or mem.eql(u8, lower, "encrypt"))
                .encrypt
            else if (mem.eql(u8, lower, "d") or mem.eql(u8, lower, "decrypt"))
                .decrypt
            else if (mem.eql(u8, lower, "v") or mem.eql(u8, lower, "version"))
                .version
            else
                error.InvalidCommand;
        }
    };
};

fn eqlFlag(s: []const u8, long: []const u8, short: []const u8) bool {
    return mem.eql(u8, s, long) or mem.eql(u8, s, short);
}

fn nextString(iter: *proc.Args.Iterator) ![]const u8 {
    const v = iter.next() orelse return error.ValueRequired;
    return v;
}

fn nextInt(comptime T: type, iter: *proc.Args.Iterator) !T {
    const v = iter.next() orelse return error.ValueRequired;
    const i = try fmt.parseInt(T, v, 10);
    return i;
}

fn nextFloat(comptime T: type, iter: *proc.Args.Iterator) !T {
    const v = iter.next() orelse return error.ValueRequired;
    const i = try fmt.parseFloat(T, v);
    return i;
}

fn getEnvPassword(env_map: *proc.Environ.Map, buf: []u8) ![]const u8 {
    const pwd = env_map.get(environ_password_key) orelse
        return error.PasswordNotProvided;
    if (pwd.len > buf.len) return error.PasswordTooLong;
    @memcpy(buf[0..pwd.len], pwd);
    return buf[0..pwd.len];
}

const help_message =
    \\flox - simple, secure, fast file encryption tool
    \\
    \\USAGE:
    \\  flox <COMMAND> [OPTIONS]
    \\
    \\COMMANDS:
    \\  e  encrypt   Encrypt a file
    \\  d  decrypt   Decrypt a file
    \\  v  version   Display flox version
    \\  h  help      Display this message
    \\
    \\OPTIONS:
    \\  encrypt:
    \\    -i  --input        path to input file (required)
    \\    -o  --output       path to output file (required or use -f)
    \\    -P  --password     encryption password
    \\    -I  --interactive  input password interactively
    \\    -f  --force        overwrite output if exists
    \\    -c  --chunk-size   chunk size in MiB (default 0.5 MiB)
    \\    -m  --memory-cost  argon2 memory cost in MiB (default 64.0 MiB)
    \\    -t  --time-cost    argon2 time cost (default 1)
    \\    -p  --parallelism  argon2 parallelism (default 1)
    \\
    \\  decrypt:
    \\    -i  --input        path to input file (required)
    \\    -o  --output       path to output file (required or use -f)
    \\    -P  --password     decryption password
    \\    -I  --interactive  input password interactively
    \\    -f  --force        overwrite output if exists
    \\
;
