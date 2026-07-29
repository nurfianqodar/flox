const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;
const Blake3 = crypto.hash.Blake3;

const Header = @import("Header.zig");
const Cipher = @import("Cipher.zig");
const ChunkLayout = @import("ChunkLayout.zig");

const Encryptor = @This();
af: std.Io.File.Atomic,

pub fn create(io: std.Io, path: []const u8, overwrite: bool) !Encryptor {
    var cwd = std.Io.Dir.cwd();

    var encryptor: Encryptor = undefined;
    encryptor.af = try cwd.createFileAtomic(io, path, .{ .replace = true });
    errdefer encryptor.af.deinit(io);

    if (encryptor.af.file_exists and !overwrite)
        return error.PathAlreadyExists;

    return encryptor;
}

pub fn deinit(encryptor: *Encryptor, io: std.Io) void {
    encryptor.af.deinit(io);
}

fn openInputFile(io: std.Io, path: []const u8) !struct { std.Io.File, std.Io.File.Stat } {
    var cwd = std.Io.Dir.cwd();
    var buf: [Header.magic_length]u8 = undefined;
    const magic = try cwd.readFile(io, path, &buf);
    if (mem.eql(u8, magic, &Header.default.magic))
        return error.AlreadyEncrypted;

    const file = try cwd.openFile(io, path, .{ .mode = .read_only });
    errdefer file.close(io);
    const stat = try file.stat(io);
    return .{ file, stat };
}

pub fn stream(
    encryptor: *Encryptor,
    io: std.Io,
    allocator: std.mem.Allocator,
    input_path: []const u8,
    cipher: *const Cipher,
    chunk_size: u32,
) !void {
    var input_file, const input_stat = try openInputFile(io, input_path);
    defer input_file.close(io);
    var input_reader = input_file.reader(io, &.{});
    const reader = &input_reader.interface;

    var output_file = encryptor.af.file;
    var output_writer = output_file.writer(io, &.{});
    const writer = &output_writer.interface;

    var cipher_meta_encoded: [Cipher.Metadata.encoded_length]u8 = undefined;
    cipher.metadata.encode(&cipher_meta_encoded);

    const chunk_layout: ChunkLayout = try .calculate(chunk_size, input_stat.size);
    var chunk_layout_encoded: [ChunkLayout.encoded_length]u8 = undefined;
    chunk_layout.encode(&chunk_layout_encoded);

    var header_vec = [_][]const u8{
        &Header.default.magic,
        &Header.default.version,
        &cipher_meta_encoded,
        &chunk_layout_encoded,
    };

    var ad: [Cipher.ad_length]u8 = undefined;

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

pub fn save(encryptor: *Encryptor, io: std.Io) !void {
    try encryptor.af.replace(io);
}

test "encrypt" {
    const t = std.testing;
    const io = t.io;
    const allocator = t.allocator;

    var enc: Encryptor = try .create(io, "/tmp/test.flox", true);
    defer enc.deinit(io);

    const meta: Cipher.Metadata = try .init(io, .{ .m = 1024, .t = 1, .p = 1 });
    var cipher: Cipher = try .init(io, allocator, meta, "secret");
    defer cipher.deinit();
    try enc.stream(io, allocator, "build.zig", &cipher, 16);
    try enc.save(io);
}
