//! header is identifier for flox file contains
//! magic and flox version

const std = @import("std");
const mem = std.mem;
const math = std.math;

/// flox magic buffer length
pub const magic_length: comptime_int = 4;

/// flox version length.
/// version is 3 bytes.
/// byte 1 = major.
/// byte 2 = minor.
/// byte 3 = patch.
pub const version_length: comptime_int = 3;

const Header = @This();
/// flox magic bytes
magic: [magic_length]u8,

/// flox version
version: [version_length]u8,

/// contains valid magic and current version
pub const default: Header = .{
    .magic = .{ 'f', 'l', 'o', 'x' },
    .version = .{ 0, 1, 1 },
};

/// this should represent default.version
pub const version_string = "0.1.1";

/// validate header
pub fn validate(header: *const Header) !void {
    if (!mem.eql(u8, &header.magic, &default.magic))
        return error.NotEncrypted;

    if (!isCompatibleVersion(&header.version))
        return error.IncompatibleVersion;
}

/// check the major and minor version is similar with current version
fn isCompatibleVersion(ver: *const [version_length]u8) bool {
    return ver[0] == default.version[0] and ver[1] == default.version[1];
}

pub const ChunkLayout = struct {
    //! Define content chunks layout
    const Cipher = @import("Cipher.zig");

    /// max size of chunk in bytes
    size: u32,

    /// count of chunk with full size
    n: u32,

    /// last chunk size in bytes
    last: u32,

    /// chunk layout encoded buffer length
    pub const encoded_length: comptime_int = 12;

    /// compute chunk layout based on chunk size and target file size
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

    /// validate the layout
    fn validate(layout: *const ChunkLayout) !void {
        if (layout.size == 0) return error.InvalidChunkSize;
        if (layout.last >= layout.size) return error.InvalidChunkLayout;
    }
};
