const std = @import("std");
const cli = @import("cli.zig");
const Command = cli.Command;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const allocator = init.gpa;
    const args = init.minimal.args;

    const command: Command = try .parse(allocator, args);
    try command.run(io, allocator, init.environ_map);
}
