pub const magic_length: comptime_int = 4;
pub const version_length: comptime_int = 3;

const Header = @This();
magic: [magic_length]u8,
version: [version_length]u8,

pub const version_string = "0.1.0";
pub const default: Header = .{
    .magic = .{ 'f', 'l', 'o', 'x' },
    .version = .{ 0, 1, 0 },
};
