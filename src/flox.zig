const std = @import("std");

pub const Encryptor = @import("flox/Encryptor.zig");
pub const Decryptor = @import("flox/Decryptor.zig");
pub const Cipher = @import("flox/Cipher.zig");
pub const Header = @import("flox/Header.zig");
pub const ChunkLayout = @import("flox/ChunkLayout.zig");
pub const utils = @import("flox/utils.zig");

test "encrypt-decrypt" {
    const t = std.testing;
    const io = t.io;
    const allocator = t.allocator;

    const content = try allocator.alloc(u8, 8192);
    defer allocator.free(content);
    io.random(content);

    const password = "secretpassword";
    const chunk_size = 16;

    {
        const metadata: Cipher.Metadata = try .init(io, .{ .m = 1024, .t = 1, .p = 1 });
        var cipher: Cipher = try .init(io, allocator, metadata, password);
        defer cipher.deinit();
        var encryptor: Encryptor = try .create(io, "/tmp/test.flox", true);
        try encryptor.stream(io, allocator, "build.zig", &cipher, chunk_size);
        try encryptor.save(io);
    }
    {
        var decryptor: Decryptor = try .open(io, "/tmp/test.flox");
        try decryptor.stream(io, allocator, password, "/tmp/test.unflox", true);
    }
}
