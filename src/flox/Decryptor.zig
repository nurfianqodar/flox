const std = @import("std");
const mem = std.mem;
const crypto = std.crypto;
const Header = @import("Header.zig");
const Cipher = @import("Cipher.zig");
const ChunkLayout = @import("ChunkLayout.zig");
const Blake3 = std.crypto.hash.Blake3;

pub fn stream(
    io: std.Io,
    allocator: std.mem.Allocator,
    input: *std.Io.File,
    output: *std.Io.File,
    password: []const u8,
) !void {
    var file_reader = input.reader(io, &.{});
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

    var cipher: Cipher = try .init(io, allocator, cipher_meta, password);
    defer cipher.deinit();

    var file_writer = output.writer(io, &.{});
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
        try cipher.decrypt(last, &ad, counter, tag);
        try writer.writeAll(last);
    }

    try writer.flush();
}
