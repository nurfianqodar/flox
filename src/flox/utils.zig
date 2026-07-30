const std = @import("std");
const mem = std.mem;
const Header = @import("Header.zig");

pub const Outfile = union(enum) {
    stdout: std.Io.File,
    atomic: std.Io.File.Atomic,

    pub fn createAtomic(io: std.Io, path: []const u8, overwrite: bool) !Outfile {
        var cwd = std.Io.Dir.cwd();
        const af = try cwd.createFileAtomic(io, path, .{ .replace = true });
        if (af.file_exists and !overwrite) return error.PathAlreadyExists;
        return .{ .atomic = af };
    }

    pub fn createStdout() Outfile {
        return .{ .stdout = std.Io.File.stdout() };
    }

    pub fn file(outfile: *Outfile) *std.Io.File {
        return switch (outfile.*) {
            .stdout => |f| &f,
            .atomic => |af| &af.file,
        };
    }

    pub fn finish(outfile: *Outfile, io: std.Io) !void {
        switch (outfile.*) {
            .stdout => return,
            .atomic => |af| {
                try af.file.sync(io);
                try af.replace(io);
            },
        }
    }

    pub fn deinit(outfile: *Outfile, io: std.Io) void {
        switch (outfile.*) {
            .stdout => return,
            .atomic => |af| af.deinit(io),
        }
    }
};

pub fn isLoxFile(io: std.Io, path: []const u8) !bool {
    var cwd = std.Io.Dir.cwd();
    var buf: [Header.magic_length]u8 = undefined;
    const magic = try cwd.readFile(io, path, &buf);
    return mem.eql(u8, magic, &Header.default.magic);
}
