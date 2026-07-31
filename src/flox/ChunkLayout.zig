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

pub fn compute(chunk_size: u32, target_size: u64) !ChunkLayout {
    if (chunk_size == 0) return error.InvalidChunkSize;
    const n = math.cast(u32, (target_size / chunk_size)) orelse return error.Overflow;
    const last = math.cast(u32, target_size % chunk_size) orelse return error.Overflow;
    return .{ .size = chunk_size, .n = n, .last = last };
}

/// encoded as size||n||last
pub fn encode(layout: *const ChunkLayout, buf: *[encoded_length]u8) void {
    var writer: std.Io.Writer = .fixed(buf);
    writer.writeInt(u32, layout.size, .little) catch unreachable;
    writer.writeInt(u32, layout.n, .little) catch unreachable;
    writer.writeInt(u32, layout.last, .little) catch unreachable;
}

/// encoded as size||n||last
pub fn decode(buf: *const [encoded_length]u8) !ChunkLayout {
    var layout: ChunkLayout = undefined;
    var reader: std.Io.Reader = .fixed(buf);

    layout.size = reader.takeInt(u32, .little) catch unreachable;
    layout.n = reader.takeInt(u32, .little) catch unreachable;
    layout.last = reader.takeInt(u32, .little) catch unreachable;

    try layout.validate();

    return layout;
}

fn validate(layout: *const ChunkLayout) !void {
    if (layout.size == 0) return error.InvalidChunkSize;
    if (layout.last > layout.size) return error.InvalidChunkLayout;
}
