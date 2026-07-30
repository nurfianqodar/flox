const std = @import("std");
const math = std.math;
const Cipher = @import("Cipher.zig");

const ChunkLayout = @This();
/// max size of chunk in bytes
size: u32,
/// count of chunk with full size
n: u32,
/// last chunk size
last: u32,

pub const encoded_length: comptime_int = 12;

pub fn calculate(chunk_size: u32, target_size: u64) !ChunkLayout {
    if (chunk_size == 0) return error.InvalidChunkSize;
    const n = math.cast(u32, (target_size / chunk_size)) orelse return error.Overflow;
    const last = math.cast(u32, target_size % chunk_size) orelse return error.Overflow;
    return .{ .size = chunk_size, .n = n, .last = last };
}

pub fn encode(layout: *const ChunkLayout, buf: *[encoded_length]u8) void {
    var w: std.Io.Writer = .fixed(buf);
    w.writeInt(u32, layout.size, .little) catch unreachable;
    w.writeInt(u32, layout.n, .little) catch unreachable;
    w.writeInt(u32, layout.last, .little) catch unreachable;
}

pub fn decode(buf: *const [encoded_length]u8) !ChunkLayout {
    var layout: ChunkLayout = undefined;
    var r: std.Io.Reader = .fixed(buf);

    layout.size = r.takeInt(u32, .little) catch unreachable;
    layout.n = r.takeInt(u32, .little) catch unreachable;
    layout.last = r.takeInt(u32, .little) catch unreachable;

    if (layout.size == 0) return error.InvalidChunkSize;
    if (layout.last > layout.size) return error.InvalidChunkSize;

    return layout;
}
