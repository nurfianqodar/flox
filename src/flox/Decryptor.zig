const std = @import("std");
const mem = std.mem;
const crypto = std.crypto;
const Header = @import("Header.zig");
const Cipher = @import("Cipher.zig");
const ChunkLayout = @import("ChunkLayout.zig");
const Blake3 = std.crypto.hash.Blake3;

fn openInputFile(io: std.Io, path: []const u8) !std.Io.File {
    var cwd = std.Io.Dir.cwd();
    var buf: [Header.magic_length]u8 = undefined;
    const magic = try cwd.readFile(io, path, &buf);
    if (!mem.eql(u8, magic, &Header.default.magic))
        return error.NotEncrypted;
    return cwd.openFile(io, path, .{ .mode = .read_only });
}

const Decryptor = @This();
file: std.Io.File,

pub fn open(io: std.Io, path: []const u8) !Decryptor {
    const file = try openInputFile(io, path);
    return .{ .file = file };
}

pub fn stream(
    decryptor: *Decryptor,
    io: std.Io,
    allocator: std.mem.Allocator,
    password: []const u8,
    output_path: []const u8,
    overwrite: bool,
) !void {
    var file_reader = decryptor.file.reader(io, &.{});
    const reader = &file_reader.interface;

    var header: Header = undefined;
    var cipher_meta_encoded: [Cipher.Metadata.encoded_length]u8 = undefined;
    var chunk_layout_encoded: [ChunkLayout.encoded_length]u8 = undefined;

    var header_vec = [_][]u8{
        &header.magic,
        &header.version,
        &cipher_meta_encoded,
        &chunk_layout_encoded,
    };

    try reader.readVecAll(header_vec[0..]);
    try header.validate();

    const cipher_meta: Cipher.Metadata = try .decode(&cipher_meta_encoded);
    const chunk_layout: ChunkLayout = try .decode(&chunk_layout_encoded);

    const chunk = try allocator.alloc(u8, chunk_layout.size);
    defer {
        crypto.secureZero(u8, chunk);
        allocator.free(chunk);
    }

    var ad: [Cipher.ad_length]u8 = undefined;
    var blalke3: Blake3 = .init(.{});
    blalke3.update(&header.magic);
    blalke3.update(&header.version);
    blalke3.update(&cipher_meta_encoded);
    blalke3.update(&chunk_layout_encoded);
    blalke3.final(&ad);

    std.debug.print("ad dec = {b64}\n", .{&ad});

    var cwd = std.Io.Dir.cwd();

    var out_af = try cwd.createFileAtomic(io, output_path, .{ .replace = true });
    defer out_af.deinit(io);

    if (out_af.file_exists and !overwrite)
        return error.PathAlreadyExsits;

    var cipher: Cipher = try .init(io, allocator, cipher_meta, password);
    defer cipher.deinit();

    var file_writer = out_af.file.writer(io, &.{});
    const writer = &file_writer.interface;

    var tag: [Cipher.tag_length]u8 = undefined;
    var counter: u32 = 0;
    for (0..chunk_layout.n) |c| {
        counter = @intCast(c);
        var chunk_vec = [_][]u8{ chunk, &tag };
        try reader.readVecAll(chunk_vec[0..]);
        try cipher.decrypt(chunk, &ad, counter, tag);
        try writer.writeAll(chunk);
    }

    counter += 1;
    if (chunk_layout.last != 0) {
        const last = chunk[0..chunk_layout.last];
        var chunk_vec = [_][]u8{ last, &tag };
        try reader.readVecAll(chunk_vec[0..]);
        std.debug.print("last tag dec = {b64}\n", .{tag});
        try cipher.decrypt(last, &ad, counter, tag);
        try writer.writeAll(last);
    }

    try writer.flush();
    try out_af.replace(io);
}
