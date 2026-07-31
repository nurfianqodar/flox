const std = @import("std");
const mem = std.mem;
const Header = @import("Header.zig");

/// check is file already encrypted
pub fn isFloxFile(io: std.Io, path: []const u8) !bool {
    var cwd = std.Io.Dir.cwd();
    var buf: [Header.magic_length]u8 = undefined;
    const magic = try cwd.readFile(io, path, &buf);
    return mem.eql(u8, magic, &Header.default.magic);
}

/// check is file exists
pub fn isFileExists(io: std.Io, path: []const u8) !bool {
    var cwd = std.Io.Dir.cwd();
    const st = cwd.statFile(io, path, .{}) catch |e| {
        switch (e) {
            error.FileNotFound => return false,
            else => return e,
        }
    };
    if (st.kind == .directory) return error.IsDir;
    return st.kind == .file;
}
