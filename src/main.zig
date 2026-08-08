const std = @import("std");
const cli = @import("cli.zig");
const Command = cli.Command;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const allocator = init.gpa;
    const args = init.minimal.args;

    var args_iter = try args.iterateAllocator(allocator);
    defer args_iter.deinit();

    _ = args_iter.skip();

    const command: Command = try .parse(&args_iter);
    try command.run(io, allocator, init.environ_map);
}
