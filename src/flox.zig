pub const version = @import("flox/Header.zig").default.version;
pub const version_string = @import("flox/Header.zig").version_string;

pub const Cipher = @import("flox/Cipher.zig");

const encryptor = @import("flox/encryptor.zig");
const decryptor = @import("flox/decryptor.zig");
pub const encryptStream = encryptor.stream;
pub const decryptStream = decryptor.stream;

const utils = @import("flox/utils.zig");
pub const isFileExists = utils.isFileExists;
pub const isFloxFile = utils.isFloxFile;

test "encrypt and decrypt stream" {
    const std = @import("std");
    const t = std.testing;
    const io = t.io;
    const allocator = t.allocator;

    const plain_path = "tests/test-data.svg";
    const enc_path = "tests/test-data.svg.flox";
    const dec_path = "tests/test-data-dec.svg";
    const password = "secretpassword";
    var cwd = std.Io.Dir.cwd();

    {
        const meta: Cipher.Metadata = try .init(io, .{ .m = 1024, .t = 1, .p = 1 });
        var cipher: Cipher = try .init(io, allocator, meta, password);
        defer cipher.deinit();

        var plain_file = try cwd.openFile(io, plain_path, .{ .mode = .read_only });
        defer plain_file.close(io);

        var enc_file = try cwd.createFile(io, enc_path, .{ .truncate = true });
        defer enc_file.close(io);

        try encryptStream(io, allocator, &plain_file, &enc_file, &cipher, 1024);
        try enc_file.sync(io);
    }

    {
        var enc_file = try cwd.openFile(io, enc_path, .{ .mode = .read_only });
        defer enc_file.close(io);

        var dec_file = try cwd.createFile(io, dec_path, .{ .truncate = true });
        defer dec_file.close(io);

        try decryptStream(io, allocator, &enc_file, &dec_file, password);

        try dec_file.sync(io);
    }

    const plain = try cwd.readFileAlloc(io, plain_path, allocator, .unlimited);
    defer allocator.free(plain);

    const dec = try cwd.readFileAlloc(io, dec_path, allocator, .unlimited);
    defer allocator.free(dec);

    try t.expectEqualSlices(u8, plain, dec);
}
