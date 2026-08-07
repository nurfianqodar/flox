//! cipher for encrypt and decrypt data

const std = @import("std");
const mem = std.mem;
const crypto = std.crypto;
const aes = crypto.aead.aes_gcm.Aes256Gcm;
const ar2 = crypto.pwhash.argon2;

/// non pirvate cipher metadata, saved at header
pub const Metadata = struct {
    pub const bnonce_length: comptime_int = nonce_length - 4;
    pub const salt_length: comptime_int = 16;
    pub const encoded_length: comptime_int = bnonce_length + salt_length + 4 + 4 + 3;

    /// base nonce (combine with counter to get nonce)
    bnonce: [bnonce_length]u8,

    /// argon2 salt
    salt: [salt_length]u8,

    /// argon2 memory cost in KiB
    m: u32,

    /// argon2 time cost
    t: u32,

    /// argon2 parallelism
    p: u24,

    /// options for generate metadata
    pub const MetadataOptions = struct {
        // argon2 memory cost in KiB
        m: u32 = 1024 * 64,

        /// argon2 iteration cost
        t: u32 = 1,

        /// argon2 parallelism
        p: u24 = 1,
    };

    /// encode metadata into a buffer.
    /// encoded as bnonce||salt||m||t||p
    pub fn encode(metadata: *const Metadata, out: *[encoded_length]u8) void {
        var w: std.Io.Writer = .fixed(out);
        w.writeAll(&metadata.bnonce) catch unreachable;
        w.writeAll(&metadata.salt) catch unreachable;
        w.writeInt(u32, metadata.m, .little) catch unreachable;
        w.writeInt(u32, metadata.t, .little) catch unreachable;
        w.writeInt(u24, metadata.p, .little) catch unreachable;
    }

    /// decode metadata from a buffer and validate it.
    /// encoded as bnonce||salt||m||t||p
    pub fn decode(buf: *const [encoded_length]u8) !Metadata {
        var metadata: Metadata = undefined;
        var r: std.Io.Reader = .fixed(buf);
        r.readSliceAll(&metadata.bnonce) catch unreachable;
        r.readSliceAll(&metadata.salt) catch unreachable;
        metadata.m = r.takeInt(u32, .little) catch unreachable;
        metadata.t = r.takeInt(u32, .little) catch unreachable;
        metadata.p = r.takeInt(u24, .little) catch unreachable;
        try metadata.validate();
        return metadata;
    }

    /// generate new metadata with random secure bnonce and salt
    pub fn init(io: std.Io, options: MetadataOptions) !Metadata {
        var metadata: Metadata = undefined;
        try io.randomSecure(&metadata.bnonce);
        try io.randomSecure(&metadata.salt);
        metadata.m = options.m;
        metadata.t = options.t;
        metadata.p = options.p;
        try metadata.validate();
        return metadata;
    }

    /// generate nonce from bnonce || counter (total length 12 bytes)
    inline fn deriveNonce(metadata: *const Metadata, counter: u32, out: *[nonce_length]u8) void {
        @memcpy(out[0..bnonce_length], &metadata.bnonce);
        mem.writeInt(u32, @ptrCast(out[bnonce_length..]), counter, .little);
    }

    /// validate memory cost, time cost, and parallelism
    ///
    /// TODO: ensure valid for argon2id
    fn validate(metadata: *const Metadata) !void {
        if (metadata.m == 0)
            return error.InvalidMemoryCost;
        if (metadata.t == 0)
            return error.InvalidTimeCost;
        if (metadata.p == 0)
            return error.InvalidParallelism;
    }

    /// generate key from password with metadata
    fn generateKey(
        metadata: *const Metadata,
        io: std.Io,
        allocator: mem.Allocator,
        password: []const u8,
        out: *[key_length]u8,
    ) !void {
        try metadata.validate();
        try ar2.kdf(
            allocator,
            out,
            password,
            &metadata.salt,
            .{ .m = metadata.m, .t = metadata.t, .p = metadata.p },
            .argon2id,
            io,
        );
    }

    /// zeroize metadata fields
    fn deinit(metadata: *Metadata) void {
        crypto.secureZero(u8, &metadata.salt);
        crypto.secureZero(u8, &metadata.bnonce);
        metadata.m = 0;
        metadata.t = 0;
        metadata.p = 0;
    }

    test "encode-decode" {
        const t = std.testing;
        const io = t.io;

        const meta: Metadata = try .init(io, .{ .m = 1024, .t = 1, .p = 1 });
        var encoded: [encoded_length]u8 = undefined;
        meta.encode(&encoded);

        var decoded: Metadata = try .decode(&encoded);

        try t.expectEqualSlices(u8, &meta.bnonce, &decoded.bnonce);
        try t.expectEqualSlices(u8, &meta.salt, &decoded.salt);
        try t.expectEqual(meta.m, decoded.m);
        try t.expectEqual(meta.t, decoded.t);
        try t.expectEqual(meta.p, decoded.p);
    }
};

/// aes256gcm key length
const key_length: comptime_int = aes.key_length;

/// aes256gcm nonce length
const nonce_length: comptime_int = aes.nonce_length;

/// aes256gcm tag length
pub const tag_length: comptime_int = aes.tag_length;

/// aes256gcm additional data length
pub const ad_length: comptime_int = 32;

const Cipher = @This();
/// key
key: [key_length]u8,

/// cipher metadata
metadata: Metadata,

pub fn init(
    io: std.Io,
    allocator: std.mem.Allocator,
    metadata: Metadata,
    password: []const u8,
) !Cipher {
    try metadata.validate();
    var cipher: Cipher = undefined;
    try metadata.generateKey(io, allocator, password, &cipher.key);
    cipher.metadata = metadata;
    return cipher;
}

/// secure zero metadata and key
pub fn deinit(cipher: *Cipher) void {
    crypto.secureZero(u8, &cipher.key);
    cipher.metadata.deinit();
}

/// encrypt data inplace.
/// nonce derived from bnonce + counter.
/// authentication tag writen to tag buffer
pub fn encrypt(
    cipher: *const Cipher,
    data: []u8,
    ad: *const [ad_length]u8,
    counter: u32,
    tag: *[tag_length]u8,
) void {
    var nonce: [nonce_length]u8 = undefined;
    cipher.metadata.deriveNonce(counter, &nonce);
    defer crypto.secureZero(u8, &nonce);
    aes.encrypt(data, tag, data, ad, nonce, cipher.key);
}

/// decrypt data inplace.
/// nonce derived from bnonce + counter.
pub fn decrypt(
    cipher: *const Cipher,
    data: []u8,
    ad: *const [ad_length]u8,
    counter: u32,
    tag: [tag_length]u8,
) !void {
    var nonce: [nonce_length]u8 = undefined;
    cipher.metadata.deriveNonce(counter, &nonce);
    defer crypto.secureZero(u8, &nonce);
    try aes.decrypt(data, data, tag, ad, nonce, cipher.key);
}

test "Cipher" {
    const t = std.testing;
    const io = t.io;
    const allocator = t.allocator;

    const metadata: Metadata = try .init(io, .{ .m = 1024, .t = 1, .p = 1 });
    const password = "secret";
    var cipher: Cipher = try .init(io, allocator, metadata, password);
    defer cipher.deinit();
    const counter: u32 = 42;
    var ad: [Cipher.ad_length]u8 = undefined;
    io.random(&ad);

    var data: [1024]u8 = undefined;
    io.random(&data);

    var plaintext: [1024]u8 = undefined;
    @memcpy(&plaintext, &data);

    var tag: [tag_length]u8 = undefined;

    try t.expectEqualSlices(u8, &plaintext, &data);

    cipher.encrypt(&data, &ad, counter, &tag);
    try t.expect(!mem.eql(u8, &data, &plaintext));

    try cipher.decrypt(&data, &ad, counter, tag);
    try t.expectEqualSlices(u8, &plaintext, &data);
}
