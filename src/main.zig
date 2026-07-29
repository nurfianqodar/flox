const std = @import("std");
const mem = std.mem;
const fmt = std.fmt;
const ascii = std.ascii;
const proc = std.process;
const flox = @import("flox");

pub fn main(init: proc.Init) !void {
    // const io = init.io;
    const allocator = init.gpa;
    const args = init.minimal.args;

    const command: Command = try .parse(allocator, args);
    std.debug.print("{any}", .{command});
}

const Command = union(Tag) {
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
                else
                    return error.InvalidOptions;
            }
            return options;
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

    fn run(command: *const Command) !void {
        switch (command.*) {
            .help => std.debug.print("Help\n", .{}),
            .version => std.debug.print("Version\n", .{}),
            .encrypt => |opt| std.debug.print("{any}\n", .{opt}),
            .decrypt => |opt| std.debug.print("{any}\n", .{opt}),
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
