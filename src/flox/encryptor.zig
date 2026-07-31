const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const Blake3 = crypto.hash.Blake3;

const Header = @import("Header.zig");
const Cipher = @import("Cipher.zig");
const ChunkLayout = @import("ChunkLayout.zig");
const utils = @import("utils.zig");

/// encrypt data from input to output with streaming
pub fn stream(
    io: std.Io,
    allocator: std.mem.Allocator,
    input: *std.Io.File,
    output: *std.Io.File,
    cipher: *const Cipher,
    chunk_size: u32,
) !void {
    if (chunk_size == 0) return error.InvalidChunkSize;

    const input_stat = try input.stat(io);
    var input_reader = input.reader(io, &.{});
    const reader = &input_reader.interface;

    var output_writer = output.writer(io, &.{});
    const writer = &output_writer.interface;

    var cipher_meta_encoded: [Cipher.Metadata.encoded_length]u8 = undefined;
    cipher.metadata.encode(&cipher_meta_encoded);

    const chunk_layout: ChunkLayout = try .compute(chunk_size, input_stat.size);
    var chunk_layout_encoded: [ChunkLayout.encoded_length]u8 = undefined;
    chunk_layout.encode(&chunk_layout_encoded);

    // encoded as magic||version||metadata||chunk_layout
    var header_vec = [_][]const u8{
        &Header.default.magic,
        &Header.default.version,
        &cipher_meta_encoded,
        &chunk_layout_encoded,
    };

    // additional data
    var ad: [Cipher.ad_length]u8 = undefined;

    // generate additional data with blake3
    // order: magic||version||cipher_meta||chunk_layout
    var blalke3: Blake3 = .init(.{});
    blalke3.update(&Header.default.magic);
    blalke3.update(&Header.default.version);
    blalke3.update(&cipher_meta_encoded);
    blalke3.update(&chunk_layout_encoded);
    blalke3.final(&ad);

    try writer.writeVecAll(header_vec[0..]);

    const chunk = try allocator.alloc(u8, @intCast(chunk_layout.size));
    defer {
        crypto.secureZero(u8, chunk);
        allocator.free(chunk);
    }

    var tag: [Cipher.tag_length]u8 = undefined;

    var counter: u32 = 0;
    for (0..chunk_layout.n) |c| {
        counter = @intCast(c);
        try reader.readSliceAll(chunk);
        cipher.encrypt(chunk, &ad, counter, &tag);
        var chunk_vec = [_][]const u8{
            chunk,
            &tag,
        };
        try writer.writeVecAll(chunk_vec[0..]);
    }
    counter += 1;
    if (chunk_layout.last != 0) {
        const last = chunk[0..chunk_layout.last];
        try reader.readSliceAll(last);
        cipher.encrypt(last, &ad, counter, &tag);
        var chunk_vec = [_][]const u8{
            last,
            &tag,
        };
        try writer.writeVecAll(chunk_vec[0..]);
    }
    try writer.flush();
}

test "encrypt" {
    const t = std.testing;
    const io = t.io;
    const allocator = t.allocator;
    _ = io;
    _ = allocator;
}
