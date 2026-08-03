const std = @import("std");

const Console = @This();

stderr_file: std.Io.File,
stderr_writer: std.Io.File.Writer,

stdout_file: std.Io.File,
stdout_writer: std.Io.File.Writer,

stdin_file: std.Io.File,
stdin_reader: std.Io.File.Reader,

pub fn init(io: std.Io, stderr_buf: ?[]u8, stdout_buf: ?[]u8, stdin_buf: []u8) Console {
    var console: Console = undefined;

    console.stderr_file = std.Io.File.stderr();
    console.stderr_writer = console.stderr_file.writer(io, stderr_buf orelse &.{});

    console.stdout_file = std.Io.File.stdout();
    console.stdout_writer = console.stdout_file.writer(io, stdout_buf orelse &.{});

    console.stdin_file = std.Io.File.stdin();
    console.stdin_reader = console.stdin_file.reader(io, stdin_buf);

    return console;
}

pub fn err(console: *Console) *std.Io.Writer {
    return &console.stderr_writer.interface;
}

pub fn out(console: *Console) *std.Io.Writer {
    return &console.stdout_writer.interface;
}

pub fn in(console: *Console) *std.Io.Reader {
    return &console.stdin_reader.interface;
}

pub fn setTerminalEcho(console: *Console, enabled: bool) !void {
    const builtin = @import("builtin");
    switch (builtin.os.tag) {
        .windows => try console.setTerminalEchoWindows(enabled),
        .linux, .freebsd, .openbsd, .netbsd, .macos => try console.setTerminalEchoPosix(enabled),
        else => return,
    }
}

pub fn promptPassword(console: *Console, prompt: []const u8, buf: []u8) ![]const u8 {
    try console.setTerminalEcho(false);
    defer console.setTerminalEcho(true) catch {};

    try console.out().print("{s}", .{prompt});
    try console.out().flush();

    var w: std.Io.Writer = .fixed(buf);
    const len = try console.in().streamDelimiterLimit(&w, '\n', .limited(buf.len));
    try console.in().discardAll(1); // discard delimiter
    if (len == 0) return error.EmptyPassword;

    try console.out().print("\n", .{});
    try console.out().flush();

    return buf[0..len];
}

fn setTerminalEchoWindows(console: *Console, enabled: bool) !void {
    // TODO
    _ = console;
    _ = enabled;
}

fn setTerminalEchoPosix(console: *Console, enabled: bool) !void {
    const posix = std.posix;
    var termios = try posix.tcgetattr(console.stdin_file.handle);
    termios.lflag.ECHO = enabled;
    try posix.tcsetattr(console.stdin_file.handle, .NOW, termios);
}

pub fn flushAll(console: *Console) !void {
    try console.stderr_writer.flush();
    try console.stdout_writer.flush();
}

test "console" {
    var console_buf: [1024 * 3]u8 = undefined;
    const ebuf = console_buf[0..1024];
    const obuf = console_buf[1024..2048];
    const ibuf = console_buf[2048..];

    var console: Console = .init(std.testing.io, ebuf, obuf, ibuf);
    try console.out().print("Hello Wordl\n", .{});
    try console.err().print("Hello Wordl\n", .{});

    var line = try console.in().takeDelimiter('\n');
    try console.out().print("{?s}\n", .{line});

    try console.setTerminalEcho(false);
    line = try console.in().takeDelimiter('\n');

    try console.out().print("{?s}\n", .{line});

    try console.setTerminalEcho(true);
    line = try console.in().takeDelimiter('\n');
    try console.out().print("{?s}\n", .{line});

    try console.flushAll();
}
