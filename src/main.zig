const std = @import("std");
const mem = std.mem;
const fmt = std.fmt;
const crypto = std.crypto;
const ascii = std.ascii;
const proc = std.process;
const flox = @import("flox");

pub fn main(init: proc.Init) !void {
    const io = init.io;
    const allocator = init.gpa;
    const args = init.minimal.args;

    const command: Command = try .parse(allocator, args);
    try command.run(io, allocator);
}

const Command = union(Tag) {
    const max_password_length: comptime_int = 1024;
    /// display help message
    help,

    /// encrypt a file
    encrypt: struct {
        const Options = @This();

        input: ?[]const u8 = null,
        output: ?[]const u8 = null,
        password: ?[]const u8 = null,
        force: bool = false,
        m: u32 = 1024 * 64,
        t: u32 = 1,
        p: u24 = 1,
        chunk_size: u32 = 1024 * 512,

        fn parse(iter: *proc.Args.Iterator) !Options {
            var options: Options = .{};
            while (iter.next()) |arg| {
                if (eqlFlag(arg, "--input", "-i"))
                    options.input = try nextString(iter)
                else if (eqlFlag(arg, "--output", "-o"))
                    options.output = try nextString(iter)
                else if (eqlFlag(arg, "--password", "-P"))
                    options.output = try nextString(iter)
                else if (eqlFlag(arg, "--force", "-f"))
                    options.force = true
                else if (eqlFlag(arg, "--memory-cost", "-m"))
                    options.m = try nextInt(u32, iter)
                else if (eqlFlag(arg, "--time-cost", "-t"))
                    options.t = try nextInt(u32, iter)
                else if (eqlFlag(arg, "--parallelism", "-p"))
                    options.p = try nextInt(u24, iter)
                else if (eqlFlag(arg, "--chunk-size", "-c"))
                    options.chunk_size = try nextInt(u32, iter)
                else
                    return error.InvalidOptions;
            }
            return options;
        }

        fn generateCipher(options: *const Options, io: std.Io, allocator: mem.Allocator) !flox.Cipher {
            var stdout_file = std.Io.File.stdout();
            var stdout_writer = stdout_file.writer(io, &.{});
            const stdout = &stdout_writer.interface;

            var stdin_file = std.Io.File.stdin();
            var stdin_buf: [max_password_length * 2]u8 = undefined;
            defer crypto.secureZero(u8, &stdin_buf);
            var stdin_reader = stdin_file.reader(io, &stdin_buf);
            const stdin = &stdin_reader.interface;

            const metadata: flox.Cipher.Metadata = try .init(io, .{
                .m = options.m,
                .t = options.t,
                .p = options.p,
            });

            const password = options.password orelse blk: {
                try stdout.print("password: ", .{});
                try stdout.flush();
                const p = try stdin.takeDelimiterInclusive('\n');
                if (p.len > max_password_length) return error.PasswordTooLong;
                const trim_p = mem.trim(u8, p, "\n");

                try stdout.print("retype password: ", .{});
                try stdout.flush();
                const pr = try stdin.takeDelimiterInclusive('\n');
                if (pr.len > max_password_length) return error.PasswordTooLong;
                const trim_pr = mem.trim(u8, pr, "\n");

                if (!mem.eql(u8, trim_p, trim_pr)) return error.PasswordNotMatch;
                break :blk trim_p;
            };

            const cipher: flox.Cipher = try .init(io, allocator, metadata, password);
            return cipher;
        }

        fn generateEncryptor(options: *const Options, io: std.Io) !flox.Encryptor {
            const output = options.output orelse (options.input orelse return error.ArgumentNotEnough);
            const encryptor: flox.Encryptor = try .create(io, output, options.force);
            return encryptor;
        }

        fn run(options: *const Options, io: std.Io, allocator: std.mem.Allocator) !void {
            var encryptor = try options.generateEncryptor(io);
            defer encryptor.deinit(io);

            var cipher = try options.generateCipher(io, allocator);
            defer cipher.deinit();

            try encryptor.stream(
                io,
                allocator,
                (options.input orelse return error.ArgumentNotEnough),
                &cipher,
                options.chunk_size,
            );
            try encryptor.save(io);
        }
    },
    decrypt: struct {
        const Options = @This();

        input: ?[]const u8 = null,
        output: ?[]const u8 = null,
        password: ?[]const u8 = null,
        force: bool = false,

        fn parse(iter: *proc.Args.Iterator) !Options {
            var options: Options = .{};

            while (iter.next()) |arg| {
                if (eqlFlag(arg, "--input", "-i"))
                    options.input = try nextString(iter)
                else if (eqlFlag(arg, "--output", "-o"))
                    options.output = try nextString(iter)
                else if (eqlFlag(arg, "--password", "-P"))
                    options.output = try nextString(iter)
                else if (eqlFlag(arg, "--force", "-f"))
                    options.force = true
                else
                    return error.InvalidOptions;
            }
            return options;
        }

        fn getInputPath(options: *const Options) ![]const u8 {
            return options.input orelse return error.ArgumentNotEnough;
        }

        fn generateDecryptor(options: *const Options, io: std.Io) !flox.Decryptor {
            const decryptor: flox.Decryptor = try .open(io, try options.getInputPath());
            return decryptor;
        }

        fn getOutputPath(options: *const Options) ![]const u8 {
            if (options.output) |o|
                return o
            else {
                if (options.force)
                    return options.input orelse return error.ArgumentNotEnough;
                return error.ArgumentNotEnough;
            }
        }

        fn run(options: *const Options, io: std.Io, allocator: mem.Allocator) !void {
            var stdout_file = std.Io.File.stdout();
            var stdout_writer = stdout_file.writer(io, &.{});
            const stdout = &stdout_writer.interface;

            var stdin_file = std.Io.File.stdin();
            var stdin_buf: [max_password_length]u8 = undefined;
            defer crypto.secureZero(u8, &stdin_buf);
            var stdin_reader = stdin_file.reader(io, &stdin_buf);
            const stdin = &stdin_reader.interface;

            var decryptor = try options.generateDecryptor(io);
            defer decryptor.deinit(io);

            const password = options.password orelse blk: {
                try stdout.print("password: ", .{});
                const p = try stdin.takeDelimiterInclusive('\n');
                const p_trim = mem.trim(u8, p, "\n");
                break :blk p_trim;
            };

            try decryptor.stream(io, allocator, password, try options.getOutputPath(), options.force);
        }
    },
    version,

    fn parse(allocator: mem.Allocator, args: proc.Args) !Command {
        var iter = try args.iterateAllocator(allocator);
        _ = iter.skip();

        const tag: Tag = try .parse(iter.next() orelse return .help);
        switch (tag) {
            .help => return .help,
            .version => return .version,
            .encrypt => return .{ .encrypt = try .parse(&iter) },
            .decrypt => return .{ .decrypt = try .parse(&iter) },
        }
    }

    fn run(command: *const Command, io: std.Io, allocator: mem.Allocator) !void {
        switch (command.*) {
            .help => std.debug.print("Help\n", .{}),
            .version => std.debug.print("Version\n", .{}),
            .encrypt => |opt| try opt.run(io, allocator),
            .decrypt => |opt| try opt.run(io, allocator),
        }
    }

    const Tag = enum {
        help,
        encrypt,
        decrypt,
        version,

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
};
