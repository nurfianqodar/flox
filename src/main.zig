const std = @import("std");
const mem = std.mem;
const fmt = std.fmt;
const crypto = std.crypto;
const ascii = std.ascii;
const proc = std.process;

const flox = @import("flox");
const Cipher = flox.Cipher;

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

    /// display current version
    version,

    /// encrypt a file
    encrypt: struct {
        const Options = @This();

        /// input file is required
        input: ?[]const u8 = null,

        /// output file is required
        output: ?[]const u8 = null,

        /// password prompted if ommited
        password: ?[]const u8 = null,

        /// overwrite output file if exists
        force: bool = false,

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
        fn parse(iter: *proc.Args.Iterator) !Options {
            var options: Options = .{};
            while (iter.next()) |arg| {
                if (eqlFlag(arg, "--input", "-i"))
                    options.input = try nextString(iter)
                else if (eqlFlag(arg, "--output", "-o"))
                    options.output = try nextString(iter)
                else if (eqlFlag(arg, "--password", "-P"))
                    options.password = try nextString(iter)
                else if (eqlFlag(arg, "--force", "-f"))
                    options.force = true
                else if (eqlFlag(arg, "--memory-cost", "-m"))
                    options.m = try nextFloat(f32, iter)
                else if (eqlFlag(arg, "--time-cost", "-t"))
                    options.t = try nextInt(u32, iter)
                else if (eqlFlag(arg, "--parallelism", "-p"))
                    options.p = try nextInt(u24, iter)
                else if (eqlFlag(arg, "--chunk-size", "-c"))
                    options.chunk_size = try nextFloat(f32, iter)
                else
                    return error.InvalidOptions;
            }
            return options;
        }

        fn getPassword(options: *const Options, io: std.Io, buf: *[max_password_length * 2]u8) ![]const u8 {
            if (options.password) |pwd| return pwd;

            var stdout_file = std.Io.File.stdout();
            var stdout_writer = stdout_file.writer(io, &.{});
            const stdout = &stdout_writer.interface;

            var stdin = std.Io.File.stdin();
            var stdin_reader = stdin.reader(io, buf);
            const reader = &stdin_reader.interface;

            // password
            try stdout.print("password: ", .{});
            try stdout.flush();
            const p = try reader.takeDelimiterInclusive('\n');
            if (p.len > max_password_length) return error.PasswordTooLong;
            const p_trim = mem.trim(u8, p, "\n");

            // password retype
            try stdout.print("retype password: ", .{});
            try stdout.flush();
            const pr = try reader.takeDelimiterInclusive('\n');
            if (pr.len > max_password_length) return error.PasswordTooLong;
            const pr_trim = mem.trim(u8, pr, "\n");

            if (!mem.eql(u8, p_trim, pr_trim)) return error.PasswordNotMatch;
            return p_trim;
        }

        fn run(options: *const Options, io: std.Io, allocator: std.mem.Allocator) !void {
            var cwd = std.Io.Dir.cwd();

            const ipath = options.input orelse return error.ArgumentNotEnough;
            if (try flox.isFloxFile(io, ipath)) return error.AlreadyEncrypted;
            var ifile = try cwd.openFile(io, ipath, .{ .mode = .read_only });
            defer ifile.close(io);

            const opath = options.output orelse ipath;
            if (try flox.isFileExists(io, opath) and !options.force) return error.PathAlreadyExists;
            var aofile = try cwd.createFileAtomic(io, opath, .{ .replace = true });
            defer aofile.deinit(io);

            const meta: Cipher.Metadata = try .init(io, .{
                // cipher meta accept in KiB while options in MiB
                .m = @intFromFloat(options.m * 1024.0),
                .t = options.t,
                .p = options.p,
            });

            var password_buf: [max_password_length * 2]u8 = undefined;
            defer crypto.secureZero(u8, &password_buf);
            const password = try options.getPassword(io, &password_buf);

            var cipher: Cipher = try .init(io, allocator, meta, password);
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
                    options.password = try nextString(iter)
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
            var cwd = std.Io.Dir.cwd();

            const ipath = options.input orelse return error.ArgumentNotEnough;
            if (!try flox.isFloxFile(io, ipath)) return error.NotEncrypted;
            var ifile = try cwd.openFile(io, ipath, .{ .mode = .read_only });
            defer ifile.close(io);

            const opath = options.output orelse ipath;
            if (try flox.isFileExists(io, opath) and !options.force)
                return error.PathAlreadyExists;
            var ofile = try cwd.createFileAtomic(io, opath, .{ .replace = true });
            defer ofile.deinit(io);

            var password_buf: [max_password_length]u8 = undefined;
            const password = try options.getPassword(io, &password_buf);

            try flox.decryptStream(io, allocator, &ifile, &ofile.file, password);
            try ofile.replace(io);
        }

        fn getPassword(options: *const Options, io: std.Io, buf: *[max_password_length]u8) ![]const u8 {
            if (options.password) |pwd| return pwd;

            var stdout_file = std.Io.File.stdout();
            var stdout_writer = stdout_file.writer(io, &.{});
            const stdout = &stdout_writer.interface;

            var stdin = std.Io.File.stdin();
            var stdin_reader = stdin.reader(io, buf);
            const reader = &stdin_reader.interface;

            // password
            try stdout.print("password: ", .{});
            try stdout.flush();
            const p = reader.takeDelimiterInclusive('\n') catch |e| {
                switch (e) {
                    error.StreamTooLong => return error.PasswordTooLong,
                    else => return e,
                }
            };
            const p_trim = mem.trim(u8, p, "\n");
            return p_trim;
        }
    },

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
        var stdout_file = std.Io.File.stdout();
        var stdout_writer = stdout_file.writer(io, &.{});
        const stdout = &stdout_writer.interface;

        switch (command.*) {
            .help => try stdout.print("{s}\n", .{help_message}),
            .version => try stdout.print("flox {s}\n", .{flox.version_string}),
            .encrypt => |opt| try opt.run(io, allocator),
            .decrypt => |opt| try opt.run(io, allocator),
        }
    }

    const Tag = enum {
        help,
        version,
        encrypt,
        decrypt,

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

    fn nextFloat(comptime T: type, iter: *proc.Args.Iterator) !T {
        const v = iter.next() orelse return error.ValueRequired;
        const i = try fmt.parseFloat(T, v);
        return i;
    }
};

const help_message =
    \\flox - simple, secure, fast file encryption tool
    \\
    \\USAGE:
    \\  flox <COMMAND> [OPTIONS]
    \\
    \\COMMANDS:
    \\  (e)ncrypt   Encrypt a file
    \\  (d)ecrypt   Decrypt a file
    \\  (v)ersion   Display flox version
    \\  (h)elp      Display this message
    \\
    \\OPTIONS:
    \\  (e)ncrypt:
    \\    -i  --input        path to input file (required)
    \\    -o  --output       path to output file (required or use -f)
    \\    -P  --password     encryption password
    \\    -c  --chunk-size   chunk size in MiB (default 0.5 MiB)
    \\    -m  --memory-cost  argon2 memory cost in MiB (default 64.0 MiB)
    \\    -t  --time-cost    argon2 time cost (default 1)
    \\    -p  --parallelism  argon2 parallelism (default 1)
    \\    -f  --force        overwrite output if exists
    \\
    \\  (d)ecrypt:
    \\    -i  --input     path to input file (required)
    \\    -o  --output    path to output file (required or use -f)
    \\    -P  --password  decryption password
    \\    -f  --force     overwrite output if exists
;
