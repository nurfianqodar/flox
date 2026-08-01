//! header is identifier for flox file contains
//! magic and flox version

const std = @import("std");
const mem = std.mem;

/// flox magic buffer length
pub const magic_length: comptime_int = 4;

/// flox version length.
/// version is 3 bytes.
/// byte 1 = major.
/// byte 2 = minor.
/// byte 3 = patch.
pub const version_length: comptime_int = 3;

const Header = @This();
magic: [magic_length]u8,
version: [version_length]u8,

/// contains valid magic and current version
pub const default: Header = .{
    .magic = .{ 'f', 'l', 'o', 'x' },
    .version = .{ 0, 1, 0 },
};

/// this should represent default.version
pub const version_string = "0.1.0";

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
